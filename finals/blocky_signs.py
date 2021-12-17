from collections import Counter

from PIL import Image

with open("blockysign.ppm.enc", "rb") as f:
    ct = f.read()

blocks = []
for i in range(0, len(ct), 16):
    blocks.append(ct[i:i+16])

common = {i[0] for i in Counter(blocks).most_common(10)}

width = 149  # A lot of trial and error.
height = len(blocks) // width

img = Image.new("RGB", (width, height))
for x in range(width):
    for y in range(height):
        block = blocks[(y * width) + x]
        img.putpixel((x, y), (255, 255, 255) if block in common else (0, 0, 0))

img.show()
