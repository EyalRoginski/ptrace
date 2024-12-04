h = input("enter hex asm: ")
chunks = [h[i : i + 16] for i in range(0, len(h), 16)]
for c in chunks:
    print(f"be64toh(0x{c}),")
