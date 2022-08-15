use std::{
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
    time::Duration,
};

const RUN_ARGS: &[&str] = &[
    "--no-reboot",
    "-nographic",
    "-device",
    "isa-debug-exit,iobase=0xf4,iosize=0x04",
    "-cpu",
    "host,+kvm",
    "-enable-kvm",
    "-m",
    "6G",
    "-object",
    "memory-backend-file,id=pc.ram,share=on,mem-path=/tmp/tyche,size=6G",
    "-machine",
    "memory-backend=pc.ram",
    "-s",
];
const TEST_ARGS: &[&str] = &[
    "--no-reboot",
    "-device",
    "isa-debug-exit,iobase=0xf4,iosize=0x04",
    "-serial",
    "stdio",
    "-display",
    "none",
    "-cpu",
    "host,+kvm",
    "-enable-kvm",
];
const TEST_TIMEOUT_SECS: u64 = 10;

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect(); // skip executable name

    let kernel_binary_path = {
        let path = PathBuf::from(args.remove(0));
        path.canonicalize().unwrap()
    };
    let no_boot = match args.iter().position(|arg| arg == "--no-run") {
        Some(idx) => {
            args.remove(idx);
            true
        }
        None => false,
    };
    let uefi = match args.iter().position(|arg| arg == "--uefi") {
        Some(idx) => {
            args.remove(idx);
            true
        }
        None => false,
    };

    let image = create_disk_images(&kernel_binary_path, uefi);

    if no_boot {
        println!("Created disk image at `{}`", image.display());
        return;
    }

    let mut run_cmd = Command::new("qemu-system-x86_64");
    run_cmd
        .arg("-drive")
        .arg(format!("format=raw,file={}", image.display()));

    if uefi {
        run_cmd.arg("-bios").arg("OVMF-pure-efi.fd");
    }

    let binary_kind = runner_utils::binary_kind(&kernel_binary_path);
    if binary_kind.is_test() {
        run_cmd.args(TEST_ARGS);

        let exit_status = run_test_command(run_cmd);
        match exit_status.code() {
            Some(33) => (), // success
            other => panic!("Test failed (exit code: {:?})", other),
        }
    } else {
        run_cmd.args(RUN_ARGS);
        run_cmd.args(&args);
        println!(
            "Running:\n{} {}",
            run_cmd.get_program().to_str().unwrap(),
            run_cmd
                .get_args()
                .map(|cmd| cmd.to_str().unwrap().to_owned())
                .fold(String::new(), |mut acc, cmd| {
                    acc.push_str(" ");
                    acc.push_str(&cmd);
                    acc
                })
        );

        let exit_status = run_cmd.status().unwrap();
        if !exit_status.success() {
            std::process::exit(exit_status.code().unwrap_or(1));
        }
    }
}

fn run_test_command(mut cmd: Command) -> ExitStatus {
    runner_utils::run_with_timeout(&mut cmd, Duration::from_secs(TEST_TIMEOUT_SECS)).unwrap()
}

pub fn create_disk_images(kernel_binary_path: &Path, uefi: bool) -> PathBuf {
    let bootloader_manifest_path = bootloader_locator::locate_bootloader("bootloader").unwrap();
    let kernel_manifest_path = locate_cargo_manifest::locate_manifest().unwrap();

    let mut build_cmd = Command::new(env!("CARGO"));
    build_cmd.current_dir(bootloader_manifest_path.parent().unwrap());
    build_cmd.arg("builder");
    build_cmd
        .arg("--kernel-manifest")
        .arg(&kernel_manifest_path);
    build_cmd.arg("--kernel-binary").arg(&kernel_binary_path);
    build_cmd
        .arg("--target-dir")
        .arg(kernel_manifest_path.parent().unwrap().join("target"));
    build_cmd
        .arg("--out-dir")
        .arg(kernel_binary_path.parent().unwrap());
    build_cmd.arg("--quiet");

    if !build_cmd.status().unwrap().success() {
        panic!("build failed");
    }

    let kernel_binary_name = kernel_binary_path.file_name().unwrap().to_str().unwrap();
    let disk_image = kernel_binary_path.parent().unwrap().join(format!(
        "boot-{}-{}.img",
        if uefi { "uefi" } else { "bios" },
        kernel_binary_name
    ));
    if !disk_image.exists() {
        panic!(
            "Disk image does not exist at {} after bootloader build",
            disk_image.display()
        );
    }
    disk_image
}
