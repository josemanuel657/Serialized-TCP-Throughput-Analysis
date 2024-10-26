import os
import dpkt
import matplotlib.pyplot as plt
import json
from multiprocessing import Pool, Process

LOG_DIR = "logs"


def plot_graph(filename, output_path):
    with open(filename, "rb") as f:
        pcap = dpkt.pcap.Reader(f)

        times = []
        sizes = []

        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)

            if not isinstance(eth.data, dpkt.ip.IP):
                continue

            times.append(ts)
            sizes.append(eth.ip.len * 8 / 1_000_000)  # Convert to Megabits

        window_size = 1  # 1 second window
        n = len(times)

        throughput_data = []
        sum_packet_sizes = 0.0
        start_index = 0

        for i in range(n):
            while times[i] - times[start_index] > window_size:
                sum_packet_sizes -= sizes[start_index]
                start_index += 1

            sum_packet_sizes += sizes[i]
            current_window_size = min(window_size, times[i] - times[start_index])
            throughput = (
                sum_packet_sizes / current_window_size if current_window_size > 0 else 0
            )
            throughput_data.append((times[i] - times[0], throughput))

        times, throughputs = zip(*throughput_data)

        plt.figure(figsize=(15, 8))
        plt.plot(times, throughputs, drawstyle="steps-post")
        plt.xlabel("Time (s)")
        plt.ylabel("Throughput (Mbps)")
        plt.title(f"Throughput over Time ({window_size}-second sliding window)")
        plt.grid(True)
        plt.savefig(output_path, dpi=300)
        plt.close()

        print("Plotted", output_path)


def plot_run(run_dir: str, run_name: str, output_dir: str):
    run_info = None

    print("Processing", run_dir)

    with open(os.path.join(run_dir, "run_info.json"), "r") as f:
        run_info = json.load(f)

    graph_prefix = f"{run_name}_SEARCH_{run_info['searchMode']}_HYSTART_{run_info['hystartEnabled']}"

    # plot_graph(
    #     os.path.join(run_dir, "client/output.pcap"),
    #     os.path.join(output_dir, f"{graph_prefix}_client.png"),
    # )
    plot_graph(
        os.path.join(run_dir, "server/output.pcap"),
        os.path.join(output_dir, f"{graph_prefix}_server.png"),
    )


def plot_multiple_runs(path: str):
    graphs_dir = os.path.join(path, "graphs")

    if os.path.exists(graphs_dir):
        print("Skipping directory", path)
        return

    os.makedirs(graphs_dir, exist_ok=True)

    with Pool(4) as p:
        for dir in os.listdir(path):
            if not dir.startswith("run"):
                continue

            p.apply_async(plot_run, (os.path.join(path, dir), dir, graphs_dir))

        p.close()
        p.join()


def main():
    if not os.path.exists(LOG_DIR):
        print("Log path doesn't exist!")
        return

    for log in os.listdir(LOG_DIR):
        path = os.path.join(LOG_DIR, log)
        if os.path.isdir(path):
            plot_multiple_runs(path)


if __name__ == "__main__":
    main()
