import os
import hashlib
import shutil
import logging
import subprocess
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger("ghostpot.cow_extractor")

class CoWExtractor:
    def __init__(self, downloads_dir: str = "data/downloads"):
        self.downloads_dir = Path(downloads_dir)
        self.downloads_dir.mkdir(parents=True, exist_ok=True)

    def extract_artifacts_from_qcow(self, qcow_path: str, session_id: str) -> List[Dict[str, Any]]:
        """
        Inspects the ephemeral qcow2 overlay before destruction to extract dropped malware binaries.
        Uses guestfish/qemu-nbd or debugfs to dump newly created files in sensitive directories.
        """
        extracted = []
        if not os.path.exists(qcow_path):
            return extracted

        mount_point = Path(f"/dev/shm/ghostpot/mnt_{session_id}")
        nbd_dev = None

        try:
            # Try mounting via qemu-nbd or loop device
            subprocess.run(["modprobe", "nbd", "max_part=8"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Find an available nbd device
            for i in range(16):
                candidate = f"/dev/nbd{i}"
                if os.path.exists(candidate):
                    # Check if free
                    res = subprocess.run(["qemu-nbd", f"--connect={candidate}", "--read-only", qcow_path], 
                                         capture_output=True, text=True)
                    if res.returncode == 0:
                        nbd_dev = candidate
                        break

            if nbd_dev:
                mount_point.mkdir(parents=True, exist_ok=True)
                mount_res = subprocess.run(["mount", "-o", "ro", nbd_dev, str(mount_point)], 
                                           capture_output=True, text=True)
                
                if mount_res.returncode == 0:
                    # Scan interesting paths: /tmp, /root, /home, /dev/shm, /var/tmp
                    scan_dirs = [mount_point / "tmp", mount_point / "root", mount_point / "dev" / "shm", mount_point / "var" / "tmp"]
                    for s_dir in scan_dirs:
                        if not s_dir.exists():
                            continue
                        for root, _, files in os.walk(s_dir):
                            for fname in files:
                                fpath = Path(root) / fname
                                if fpath.is_file() and not fpath.is_symlink() and fpath.stat().st_size > 0:
                                    # Read and hash
                                    try:
                                        with open(fpath, "rb") as f:
                                            content = f.read()
                                        
                                        shasum = hashlib.sha256(content).hexdigest()
                                        dest_path = self.downloads_dir / shasum
                                        
                                        if not dest_path.exists():
                                            with open(dest_path, "wb") as f_out:
                                                f_out.write(content)
                                        
                                        extracted.append({
                                            "shasum": shasum,
                                            "filename": fname,
                                            "size": len(content),
                                            "saved_path": str(dest_path),
                                            "url": f"local://{fpath.relative_to(mount_point)}"
                                        })
                                        logger.info(f"[+] Extracted dropped malware: {fname} (SHA256: {shasum[:12]}..., Size: {len(content)}B)")
                                    except Exception as err:
                                        logger.debug(f"Error reading file {fpath}: {err}")
        except Exception as e:
            logger.debug(f"CoW extraction failed for {qcow_path}: {e}")
        finally:
            # Clean unmount
            if mount_point.exists():
                subprocess.run(["umount", str(mount_point)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    mount_point.rmdir()
                except Exception:
                    pass
            if nbd_dev:
                subprocess.run(["qemu-nbd", f"--disconnect={nbd_dev}"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        return extracted
