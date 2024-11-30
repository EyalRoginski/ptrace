def main():
    with open("tracy-server", "rb") as server_file:
        with open("pipe", "r") as pipe:
            contents = server_file.read()
            while True:
                search_for = pipe.readline().strip()
                if not search_for:
                    continue
                print(f"Searching for {search_for}")
                bytes_to_search_for = bytes(
                    [
                        int(search_for[c : c + 2], base=16)
                        for c in range(0, len(search_for), 2)
                    ]
                )
                index = contents.find(bytes_to_search_for)
                with open("pipe", "w") as pipe_write:
                    print(index)
                    if index == -1:
                        print("Didn't find it...")
                        pipe_write.write("0")
                    else:
                        print("Found it!")
                        pipe_write.write(f"{hex(index)}")


if __name__ == "__main__":
    main()
