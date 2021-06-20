import matplotlib.pyplot as plt
import numpy as np

results_file = open("/tmp/results-data.txt", "r")
num_bytes_x = []
num_cycles_y = []
for line in results_file:
    tokens = line.split(" ")
    num_bytes = int(tokens[0])
    num_cycles = int(tokens[2])
    num_bytes_x.append(num_bytes)
    num_cycles_y.append(num_cycles)
results_file.close()

plt.xticks(
    np.array([32 * 1024, 128 * 1024, 256 * 1024, 512 * 1024, 1024 * 1024]),
    ["32K", "128K", "256K", "512K", "1M"])
plt.plot(np.array(num_bytes_x), np.array(num_cycles_y))
plt.show()
