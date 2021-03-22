import struct

sub = {1:0, 5:1, 6:2, 4:3, 3:4, 2:5, 7:6, 0:7, 8:8}

def print_board(pieces):
    board = []
    for piece in pieces:
        board += [sub[piece[0]]]*piece[1]
    
    print("_"*10)
    for i in range(23, 0, -1):
        blop = board[10*i:10*i+10]
        z = [str(i) if i != 7 else " " for i in blop]
        print("".join(z) + "|")




def main():
    tetr = open("secret.tetr", "rb")
    buf = tetr.read()
    tetr.close()

    if buf[0:8] != b"TETR" + b"\x00"*4:
        return
    buf = buf[8:]

    while len(buf) > 0:
        # 0xf0 means a new board
        if buf[0] == 0xf0:
            pieces = []
            buf = buf[1:]
        
        # Decode an array of elements
        pieces.append(struct.unpack("<BI", buf[0:5]))
        buf = buf[5:]

        if buf[0] == 0xf1:
            print_board(pieces)
            buf = buf[1:]

main()