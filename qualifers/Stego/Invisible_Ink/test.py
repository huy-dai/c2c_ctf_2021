from PIL import Image
import os

os.chdir("./Stego/Invisible_Ink")

img = Image.open('flag.png','r')
pix = img.load()

n_img = Image.new(img.mode,img.size)
n_pix = n_img.load()

for x in range(img.size[0]):
    for y in range(img.size[1]):
        if pix[x,y] == 1:
            n_pix[x,y] = 255
        else:
            n_pix[x,y] = 1

n_img.show()
n_img.save("new_image.png")