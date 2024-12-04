h = "5048B8F0DEBC9A78563412FFE0"
chunks = [h[i : i + 16] for i in range(0, len(h), 16)]
for c in chunks:
    print(f"be64toh(0x{c}),")
