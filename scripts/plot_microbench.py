import matplotlib.pyplot as plt
import numpy as np

class PlotInfo:
    def __init__(self, x_ticks, x_labels, title, x_axis_name, y_axis_name):
        self.x_ticks = x_ticks
        self.x_labels = x_labels
        self.title = title
        self.x_axis_name = x_axis_name
        self.y_axis_name = y_axis_name

def plot_data(file_name, plot_info):
    results_file = open(file_name, "r")
    num_bytes_x = []
    num_cycles_y = []
    for line in results_file:
        tokens = line.split(" ")
        num_bytes = int(tokens[0])
        num_cycles = int(tokens[2])
        num_bytes_x.append(num_bytes)
        num_cycles_y.append(num_cycles)
    results_file.close()

    plt.xlabel(plot_info.x_axis_name)
    plt.ylabel(plot_info.y_axis_name)
    plt.xticks(np.array(plot_info.x_ticks), plot_info.x_labels)
    plt.title(plot_info.title)
    plt.plot(np.array(num_bytes_x), np.array(num_cycles_y))
    plt.show()

# Instruction cache
plot_data("/tmp/results-instr-cache.txt",
    PlotInfo(
            x_ticks=[32 * 1024, 128 * 1024, 256 * 1024, 512 * 1024, 1024 * 1024],
            x_labels=["32K", "128K", "256K", "512K", "1024K"],
            title="Instruction cache and latency",
            x_axis_name="Cache size (Kib)",
            y_axis_name="Latency (cycles)"))

plot_data("/tmp/results-data-cache.txt",
    PlotInfo(
            x_ticks=[32 * 1024, 128 * 1024, 256 * 1024, 512 * 1024, 1024 * 1024],
            x_labels=["32K", "128K", "256K", "512K", "1024K"],
            title="Data cache and latency",
            x_axis_name="Cache size (Kib)",
            y_axis_name="Latency (cycles)"))

plot_data("/tmp/results-data-page.txt",
    PlotInfo(
            x_ticks=[32, 64, 256, 512, 1024],
            x_labels=["16", "64", "256", "512", "1024"],
            title="dTLB size and latency",
            x_axis_name="Num pages",
            y_axis_name="Latency (cycles)"))

plot_data("/tmp/results-instr-page.txt",
    PlotInfo(
            x_ticks=[32, 64, 256, 512, 1024],
            x_labels=["16", "64", "256", "512", "1024"],
            title="iTLB size and latency",
            x_axis_name="Num pages",
            y_axis_name="Latency (cycles)"))

