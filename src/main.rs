use clap::{Arg, Command};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    path::Path,
    process::Command as SysCommand,
    thread,
    time::Duration,
};

#[derive(Serialize, Deserialize)]
struct ResumeState {
    scanned_batches: HashSet<usize>,
}

fn main() {
    let matches = Command::new("PCI Segmentation Scanner")
        .version("1.0")
        .author("Your Name")
        .about("Runs segmentation scans using Nmap or Masscan")
        .arg(Arg::new("hostfile").required(true))
        .arg(Arg::new("portscope").required(true).value_parser(["top100", "top1000", "top10000", "all"]))
        .arg(Arg::new("protocol").required(true).value_parser(["tcp", "udp", "both"]))
        .arg(Arg::new("sourceip").required(true))
        .arg(Arg::new("output").required(true))
        .arg(Arg::new("scanner").required(true).value_parser(["nmap", "masscan"]))
        .get_matches();

    let hostfile = matches.get_one::<String>("hostfile").unwrap();
    let portscope = matches.get_one::<String>("portscope").unwrap();
    let protocol = matches.get_one::<String>("protocol").unwrap();
    let source_ip = matches.get_one::<String>("sourceip").unwrap();
    let output_base = matches.get_one::<String>("output").unwrap();
    let scanner = matches.get_one::<String>("scanner").unwrap();

    let port_range = match portscope.as_str() {
        "top100" => " --top-ports 100",
        "top1000" => "",
        "top10000" => " --top-ports 10000",
        "all" => " -p-",
        _ => "",
    };

    let hosts = read_hosts(hostfile);
    let batches = chunk_hosts(&hosts, 20);
    let resume_path = format!("{}_resume.json", output_base);
    let mut resume_state = load_resume_state(&resume_path);

    let mut all_results: Vec<ScanResult> = Vec::new();

    for (i, batch) in batches.iter().enumerate() {
        if resume_state.scanned_batches.contains(&i) {
            continue;
        }

        println!("\nScanning batch {}/{}", i + 1, batches.len());

        if protocol == "tcp" || protocol == "both" {
            let results = run_scan(scanner, batch, "tcp", port_range, i);
            all_results.extend(results);
        }

        if protocol == "udp" || protocol == "both" {
            warn_udp(scanner);
            let results = run_scan(scanner, batch, "udp", port_range, i);
            all_results.extend(results);
        }

        resume_state.scanned_batches.insert(i);
        save_resume_state(&resume_path, &resume_state);

        println!("Press ENTER to continue, or type 'pause' to pause.");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        if input.trim() == "pause" {
            println!("Paused. Press ENTER to resume...");
            std::io::stdin().read_line(&mut input).unwrap();
        }
    }

    std::fs::remove_file(&resume_path).ok();

    write_csv(&all_results, &format!("{}_scan.csv", output_base));
    write_compliance_summary(&all_results, &format!("{}_compliance.csv", output_base));
    write_html_report(&all_results, source_ip, &format!("{}_report.html", output_base));

    println!("\nScan complete. Reports saved.");
}

#[derive(Debug, Serialize, Deserialize)]
struct ScanResult {
    ip: String,
    protocol: String,
    port: u16,
    state: String,
}

fn read_hosts(path: &str) -> Vec<String> {
    let file = File::open(path).expect("Failed to open host file");
    BufReader::new(file)
        .lines()
        .filter_map(Result::ok)
        .filter(|line| !line.is_empty())
        .collect()
}

fn chunk_hosts(hosts: &[String], chunk_size: usize) -> Vec<Vec<String>> {
    hosts.chunks(chunk_size).map(|c| c.to_vec()).collect()
}

fn load_resume_state(path: &str) -> ResumeState {
    if Path::new(path).exists() {
        let data = fs::read_to_string(path).unwrap();
        serde_json::from_str(&data).unwrap()
    } else {
        ResumeState {
            scanned_batches: HashSet::new(),
        }
    }
}

fn save_resume_state(path: &str, state: &ResumeState) {
    let data = serde_json::to_string_pretty(state).unwrap();
    fs::write(path, data).unwrap();
}

fn warn_udp(scanner: &str) {
    if scanner == "masscan" {
        println!("WARNING: Masscan does not support UDP. Skipping.");
        thread::sleep(Duration::from_secs(2));
    }
}

fn run_scan(scanner: &str, hosts: &[String], protocol: &str, port_opts: &str, batch_num: usize) -> Vec<ScanResult> {
    let hostlist = hosts.join(" ");
    let outfile = format!("scan_batch{}_{}.txt", batch_num, protocol);

    let cmd = match scanner {
        "nmap" => {
            let flag = if protocol == "tcp" { "-sS" } else { "-sU" };
            format!("nmap {} -Pn -T4 {} {} -oG {}", flag, port_opts, hostlist, outfile)
        }
        "masscan" if protocol == "tcp" => {
            let ports = match port_opts {
                " --top-ports 100" => "0-1024",
                " --top-ports 10000" => "0-65535",
                _ => "0-65535",
            };
            format!("masscan {} -p{} --rate 1000 -oL {}", hostlist, ports, outfile)
        }
        _ => return vec![],
    };

    println!("Running: {}", cmd);
    let _ = SysCommand::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .expect("failed to run scanner");

    parse_scan_output(&outfile, protocol)
}

fn parse_scan_output(file: &str, protocol: &str) -> Vec<ScanResult> {
    let content = fs::read_to_string(file).unwrap_or_default();
    let mut results = vec![];

    for line in content.lines() {
        if line.starts_with("Host:") || line.contains("Ports:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 4 && parts[0] == "Host:" {
                let ip = parts[1].to_string();
                if let Some(port_info) = line.split("Ports:").nth(1) {
                    for port_chunk in port_info.split(",") {
                        let port_fields: Vec<&str> = port_chunk.trim().split("/").collect();
                        if port_fields.len() > 1 && port_fields[1] == "open" {
                            if let Ok(port) = port_fields[0].parse::<u16>() {
                                results.push(ScanResult {
                                    ip: ip.clone(),
                                    protocol: protocol.to_uppercase(),
                                    port,
                                    state: "open".into(),
                                });
                            }
                        }
                    }
                }
            }
        } else if line.starts_with("open") && file.ends_with(".txt") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                results.push(ScanResult {
                    ip: parts[3].to_string(),
                    protocol: protocol.to_uppercase(),
                    port: parts[2].parse().unwrap_or(0),
                    state: "open".to_string(),
                });
            }
        }
    }

    results
}

fn write_csv(results: &[ScanResult], file_path: &str) {
    let mut wtr = csv::Writer::from_path(file_path).unwrap();
    wtr.write_record(&["IP Address", "Protocol", "Port", "Port State"]).unwrap();
    for r in results {
        wtr.write_record(&[&r.ip, &r.protocol, &r.port.to_string(), &r.state])
            .unwrap();
    }
    wtr.flush().unwrap();
}

fn write_compliance_summary(results: &[ScanResult], file_path: &str) {
    let mut summary: Vec<(String, usize)> = vec![];
    let mut map = std::collections::HashMap::new();
    for r in results {
        map.entry(&r.ip).or_insert_with(Vec::new).push(r.port);
    }

    let mut wtr = csv::Writer::from_path(file_path).unwrap();
    wtr.write_record(&["IP Address", "Open Ports", "Open Port List", "Compliance Status"]).unwrap();
    for (ip, ports) in map {
        let open_ports: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
        let status = if ports.is_empty() { "PASS" } else { "FAIL" };
        wtr.write_record(&[ip, &ports.len().to_string(), &open_ports.join(", "), status])
            .unwrap();
    }
    wtr.flush().unwrap();
}

fn write_html_report(results: &[ScanResult], source_ip: &str, file_path: &str) {
    let mut html = String::from(r#"<!DOCTYPE html><html><head><style>
        body { font-family: Arial; padding: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ccc; padding: 8px; }
        th { background-color: #f2f2f2; }
        .pass { background-color: #d4edda; }
        .fail { background-color: #f8d7da; }
    </style></head><body>"#);

    html.push_str(&format!("<h2>PCI Segmentation Compliance Report</h2><p><strong>Source IP:</strong> {}</p>", source_ip));
    html.push_str("<table><tr><th>IP Address</th><th>Port</th><th>Protocol</th><th>Status</th></tr>");
    for r in results {
        html.push_str(&format!(
            "<tr class=\"{}\"><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            if r.state == "open" { "fail" } else { "pass" },
            r.ip,
            r.port,
            r.protocol,
            r.state
        ));
    }
    html.push_str("</table></body></html>");

    fs::write(file_path, html).unwrap();
}
