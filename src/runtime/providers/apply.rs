//! Live configuration uses the same immutable graphs and publication as providers.
use super::*;
use crate::resource::config_apply::{ApplyError, ApplyRequest, ConfigUpdate};

impl ProviderRuntime {
    async fn refresh_geodata(&self, cancel: &CancellationToken) -> Result<(), ApplyError> {
        let current = self.current.load_full();
        let Some(config) = &current.config.geodata_update else {
            return Ok(());
        };
        let service = GeoDataUpdateService::new(
            self.manager.clone(),
            current.dispatcher.clone(),
            self.lease.clone(),
            config.urls.clone(),
            config.geodata_mode,
            current.config.global_ua.clone(),
            current.config.etag_support,
            false,
            self.security.clone(),
        );
        service.refresh_active(cancel.clone()).await.map_err(|_| {
            if cancel.is_cancelled() {
                ApplyError::Stopped
            } else {
                ApplyError::PreparationFailed
            }
        })
    }

    async fn flush_fake_ip(&self, cancel: &CancellationToken) -> Result<(), ApplyError> {
        if cancel.is_cancelled() {
            return Err(ApplyError::Stopped);
        }
        let current = self.current.load_full();
        if let Some(dns) = &current.dns {
            // The worker joins this future even if its caller/Stop cancels it;
            // never detach the already-started durable database transaction.
            dns.flush_fake_ip()
                .await
                .map_err(|_| ApplyError::PreparationFailed)?;
        }
        if cancel.is_cancelled() {
            Err(ApplyError::Stopped)
        } else {
            Ok(())
        }
    }

    pub(super) async fn apply_request(&self, mut request: ApplyRequest) {
        let cancellation = request.cancellation();
        let update = request.take_update();
        let result = self.apply_update(update, cancellation).await;
        request.complete(result);
    }
    async fn apply_update(
        &self,
        update: ConfigUpdate,
        cancel: CancellationToken,
    ) -> Result<(), ApplyError> {
        if cancel.is_cancelled() {
            return Err(ApplyError::Stopped);
        }
        match &update {
            // Implementations are supplied by the shared maintenance adapter;
            // these commands occupy the same admission and worker as reloads.
            ConfigUpdate::RefreshGeoData => return self.refresh_geodata(&cancel).await,
            ConfigUpdate::FlushFakeIp => return self.flush_fake_ip(&cancel).await,
            _ => {}
        }
        if matches!(&update,ConfigUpdate::Patch(patch) if patch.is_empty()) {
            return Ok(());
        }
        let current = self.current.load_full();
        let previous = current.clone();
        let directory = self
            .manager
            .store_dir()
            .parent()
            .ok_or(ApplyError::PreparationFailed)?
            .to_path_buf();
        let dialer = self.dialer.clone();
        let limits = self.limits;
        let geo = self.geo.clone();
        let security = self.security.clone();
        let blocking_cancel = cancel.clone();
        // The provider worker owns and awaits every started blocking task. No
        // response/adapter cancellation can detach parsing or graph preparation.
        let prepared = tokio::task::spawn_blocking(move || {
            if blocking_cancel.is_cancelled() {
                return Err(ApplyError::Stopped);
            }
            let patch = matches!(&update, ConfigUpdate::Patch(_));
            let template = match update {
                ConfigUpdate::Replace(yaml) => {
                    crate::config::providers::ProviderTemplate::update_yaml(
                        yaml.as_bytes(),
                        &directory,
                    )
                }
                ConfigUpdate::Patch(patch) => previous
                    .config
                    .providers
                    .as_ref()
                    .ok_or(ApplyError::PreparationFailed)?
                    .patched(&patch),
                ConfigUpdate::RefreshGeoData | ConfigUpdate::FlushFakeIp => {
                    unreachable!("maintenance handled before candidate construction")
                }
            }
            .map_err(|_| ApplyError::InvalidConfig)?;
            let cache = ProviderCache::open_candidate(&directory, template, &blocking_cancel)
                .map_err(|_| {
                    if blocking_cancel.is_cancelled() {
                        ApplyError::Stopped
                    } else {
                        ApplyError::PreparationFailed
                    }
                })?;
            let mut config = cache
                .template
                .materialize_with_cancel(&cache.contents, Some(&blocking_cancel))
                .map_err(|_| {
                    if blocking_cancel.is_cancelled() {
                        ApplyError::Stopped
                    } else {
                        ApplyError::InvalidConfig
                    }
                })?;
            if !crate::config::live_update::startup_compatible(&previous.config, &config) {
                return Err(ApplyError::RestartRequired);
            }
            if patch {
                config.dns.hosts = previous.config.dns.hosts.clone();
            } else {
                crate::dns::hosts::materialize_lan(&mut config.dns.hosts)
                    .map_err(|_| ApplyError::PreparationFailed)?;
            }
            let requirements =
                GeoRequirements::for_config(&config).map_err(|_| ApplyError::InvalidConfig)?;
            let rules =
                RuleSet::compile_config(&mut config).map_err(|_| ApplyError::InvalidConfig)?;
            if blocking_cancel.is_cancelled() {
                return Err(ApplyError::Stopped);
            }
            let parts = GraphBuilder {
                security,
                connections: previous.connections.clone(),
                config: config.clone(),
                endpoints: vec![PreparedProxyEndpoints::default(); config.proxies.len()],
                limits,
                rules,
                geo_matcher: geo,
                previous_dns: previous.dns.clone(),
                data_dir: Some(directory),
            }
            .build(dialer)
            .map_err(|_| ApplyError::PreparationFailed)?;
            Ok((cache, config, parts, requirements))
        })
        .await
        .map_err(|_| ApplyError::PreparationFailed)??;
        let (cache, config, parts, requirements) = prepared;
        let next = Arc::new(Generation::from_parts(config, &parts, requirements.clone()));
        drop(parts);
        // The validated graph is ready before confined cache directories are
        // created. This joined task never writes a resource body or metadata.
        let directory = self
            .manager
            .store_dir()
            .parent()
            .ok_or(ApplyError::PreparationFailed)?
            .to_owned();
        let paths_cancel = cancel.clone();
        let prepared_cache = tokio::task::spawn_blocking(move || {
            cache
                .prepare_paths(&directory, &paths_cancel)
                .map(|()| cache)
        })
        .await;
        let cache = match prepared_cache {
            Ok(Ok(cache)) => cache,
            _ => {
                next.graph.begin_shutdown();
                next.graph.shutdown().await;
                return Err(if cancel.is_cancelled() {
                    ApplyError::Stopped
                } else {
                    ApplyError::PreparationFailed
                });
            }
        };
        if cancel.is_cancelled() {
            next.graph.begin_shutdown();
            next.graph.shutdown().await;
            return Err(ApplyError::Stopped);
        }
        let combined = match self.combined_requirements(&requirements) {
            Ok(value) => value,
            Err(_) => {
                next.graph.begin_shutdown();
                next.graph.shutdown().await;
                return Err(ApplyError::PreparationFailed);
            }
        };
        let manager = self.manager.clone();
        let lease = self.lease.clone();
        let blocking_cancel = cancel.clone();
        let registered = tokio::task::spawn_blocking(move || {
            manager.replace_requirements(&lease, combined, &blocking_cancel)
        })
        .await;
        if !matches!(registered, Ok(Ok(()))) {
            next.graph.begin_shutdown();
            next.graph.shutdown().await;
            self.restore_requirements().await;
            return Err(if cancel.is_cancelled() {
                ApplyError::Stopped
            } else {
                ApplyError::PreparationFailed
            });
        }
        // Acquire asynchronous locks before the short publication mutex. New
        // cache admissions and old results cannot cross this shared DNS epoch.
        let mut active_cache = self.cache.lock().await;
        let dns_boundary = match next.dns.as_ref().or(current.dns.as_ref()) {
            Some(dns) => Some(dns.configuration_publication().await),
            None => None,
        };
        // Config updates and provider refreshes use the same serial worker.
        let result = {
            let _publication = self.publication.lock().unwrap();
            if cancel.is_cancelled() || self.cancellation.is_cancelled() {
                Err(ApplyError::Stopped)
            } else {
                for (index, state) in current.groups.list_states().into_iter().enumerate() {
                    let forced = current.groups.selection(index).forced().is_some();
                    let _ = next
                        .groups
                        .inherit_selection(&state.name, &state.now, forced);
                }
                if let Some(dns) = &current.dns {
                    dns.retire_configuration_hints();
                }
                for generation in self.retired.lock().unwrap().iter() {
                    if let Some(dns) = &generation.dns {
                        dns.retire_configuration_hints();
                    }
                }
                let old = self.current.swap(next.clone());
                *active_cache = cache;
                self.record_states(&active_cache);
                self.retired.lock().unwrap().push(old);
                if let Some(logs) = &self.logs {
                    logs.set_level(next.config.log_level);
                }
                Ok(())
            }
        };
        drop(dns_boundary);
        drop(active_cache);
        if result.is_err() {
            next.graph.begin_shutdown();
            next.graph.shutdown().await;
            self.restore_requirements().await;
        }
        result
    }
    async fn restore_requirements(&self) {
        let current = self.current.load_full();
        let Ok(requirements) = self.combined_requirements(&current.requirements) else {
            return;
        };
        let manager = self.manager.clone();
        let lease = self.lease.clone();
        // Restoration is a local registration operation. It must complete even
        // after Stop/caller cancellation to keep the still-live lease valid.
        let cancel = CancellationToken::new();
        let _ = tokio::task::spawn_blocking(move || {
            manager.replace_requirements(&lease, requirements, &cancel)
        })
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{dialer::SystemResolver, resource::config_apply::ConfigPatch};
    #[tokio::test]
    async fn config_candidates_preserve_old_generation_and_latest_provider_template() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("nodes.yaml");
        std::fs::write(&file, b"proxies: [{name: old, type: direct}]\n").unwrap();
        let yaml = |extra: &str| {
            format!(
                "{extra}\nproxy-providers: {{remote: {{type: file, path: nodes.yaml}}}}\nproxy-groups: [{{name: chosen, type: select, use: [remote]}}]\nrules: ['MATCH,chosen']\n"
            )
        };
        let manager =
            GeoDataManager::open(&root.path().join("geodata"), Duration::from_secs(86400)).unwrap();
        let prepared = PreparedCore::prepare_config(
            Config::parse_yaml(yaml("").as_bytes()).unwrap(),
            manager,
            &SystemResolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        let parts = prepared.build_dispatcher(Dialer::default()).unwrap();
        let live = parts.resources.clone().unwrap();
        let old = live.current.load_full();
        assert!(matches!(
            live.apply_update(
                ConfigUpdate::Replace("rules: ['MATCH,missing']\n".into()),
                CancellationToken::new()
            )
            .await,
            Err(ApplyError::InvalidConfig)
        ));
        assert!(Arc::ptr_eq(&old, &live.current.load_full()));
        let resource_change = yaml("mixed-port: 1080");
        assert_eq!(
            live.apply_update(
                ConfigUpdate::Replace(resource_change),
                CancellationToken::new()
            )
            .await,
            Err(ApplyError::RestartRequired)
        );
        assert!(Arc::ptr_eq(&old, &live.current.load_full()));
        live.apply_update(
            ConfigUpdate::Patch(ConfigPatch {
                tcp_concurrent: Some(true),
                ..Default::default()
            }),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(live.current.load().config.connections.tcp_concurrent);
        assert!(!old.config.connections.tcp_concurrent);
        assert!(Arc::ptr_eq(
            &old.connections,
            &live.current.load().connections
        ));
        let next = yaml("mode: direct\nlog-level: warning\ntcp-concurrent: true");
        live.apply_update(ConfigUpdate::Replace(next), CancellationToken::new())
            .await
            .unwrap();
        std::fs::write(&file, b"proxies: [{name: fresh, type: direct}]\n").unwrap();
        live.update(0).await.unwrap();
        assert_eq!(live.current.load().config.mode, crate::config::Mode::Direct);
        assert!(live.current.load().config.connections.tcp_concurrent);
        assert_eq!(live.groups().state("chosen").unwrap().now, "fresh");
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert_eq!(
            live.apply_update(
                ConfigUpdate::Patch(ConfigPatch {
                    mode: Some("rule".into()),
                    ..Default::default()
                }),
                cancelled
            )
            .await,
            Err(ApplyError::Stopped)
        );
        assert_eq!(live.current.load().config.mode, crate::config::Mode::Direct);
        live.shutdown().await;
    }
}
