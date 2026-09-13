import os
import secrets
import random
import yaml
from pathlib import Path
from pydantic import BaseModel, Field
from typing import Optional


class ServiceSSHConfig(BaseModel):
    enabled: bool = True
    listen_port: int = 22
    target_port: int = 2222


class ServiceTelnetConfig(BaseModel):
    enabled: bool = True
    listen_port: int = 23
    target_port: int = 2323


class ServicesConfig(BaseModel):
    ssh: ServiceSSHConfig = Field(default_factory=ServiceSSHConfig)
    telnet: ServiceTelnetConfig = Field(default_factory=ServiceTelnetConfig)


class WebConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = Field(default_factory=lambda: random.randint(20000, 58000))
    secret_slug: str = Field(default_factory=lambda: f"ghost_{secrets.token_hex(6)}")
    title: str = "GHOSTPOT // Honeypot Intelligence Center"


class VMConfig(BaseModel):
    pool_size: int = 2
    memory_mb: int = 128
    vcpus: int = 1
    use_kvm: Optional[bool] = None
    kernel_path: str = "kernel/vmlinuz"
    rootfs_path: str = "rootfs/alpine-rootfs.raw"
    tmpfs_dir: str = "/dev/shm/ghostpot"


class StorageConfig(BaseModel):
    db_path: str = "data/ghostpot.db"
    downloads_dir: str = "data/downloads"


class AuthConfig(BaseModel):
    mode: str = "dynamic"  # "dynamic", "accept_all", "fixed"
    allow_none_auth: bool = False      # Allow execution without password attempt (none auth)
    allow_publickey: bool = True       # Accept any public key
    require_password: bool = True      # Require password before granting shell access
    min_attempts: int = 1
    max_attempts: int = 3
    cache_ttl_hours: int = 24



class BandwidthConfig(BaseModel):
    mode: str = "randomized"  # "randomized", "fixed", "unlimited"
    min_rate_kbps: int = 1500
    max_rate_kbps: int = 8000
    jitter_ms: int = 15


class ThreatScoringConfig(BaseModel):
    enabled: bool = True
    max_score_threshold: int = 100
    penalty_private_lan: int = 40
    penalty_syn_flood: int = 35
    penalty_destructive_cmd: int = 30


class NetworkConfig(BaseModel):
    outbound_enabled: bool = True
    block_private_subnets: bool = True
    block_spam_ports: list[int] = Field(default_factory=lambda: [25, 465, 587, 445, 139])
    bandwidth: BandwidthConfig = Field(default_factory=BandwidthConfig)
    threat_scoring: ThreatScoringConfig = Field(default_factory=ThreatScoringConfig)


class AppConfig(BaseModel):
    services: ServicesConfig = Field(default_factory=ServicesConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    web: WebConfig = Field(default_factory=WebConfig)
    vm: VMConfig = Field(default_factory=VMConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)

    def is_kvm_available(self) -> bool:
        if self.vm.use_kvm is not None:
            return self.vm.use_kvm
        return os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK)


def load_config(config_path: str = "config.yaml") -> AppConfig:
    path = Path(config_path)
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        config = AppConfig(**data)
    else:
        config = AppConfig()
        # Save default generated config
        save_config(config, config_path)
    
    # Ensure directories exist
    os.makedirs(os.path.dirname(config.storage.db_path) or ".", exist_ok=True)
    os.makedirs(config.storage.downloads_dir, exist_ok=True)
    os.makedirs(config.vm.tmpfs_dir, exist_ok=True)
    
    return config


def save_config(config: AppConfig, config_path: str = "config.yaml") -> None:
    path = Path(config_path)
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(config.model_dump(), f, default_flow_style=False, sort_keys=False)
