import numpy as np
import os
import array
import imageio 
from PIL import Image

class IMAGE_feature():

    def __init__(self, in_path, out_path):
        self.in_path = in_path
        self.out_path = out_path

    def get_image(self, path, file):
        filename = path + file

        try:
            f = open(filename, 'rb')
            ln = os.path.getsize(filename)

            if ln == 0:
                print(f"[ERROR] File {file} is empty. Skipping.")
                return

            width = int(ln**0.5)

            if width == 0:  # if file = 0 skip!!
                print(f"[ERROR] Invalid width for file {file}. Skipping.")
                return

            rem = ln % width
            a = array.array("B")
            a.fromfile(f, ln - rem)
            f.close()

            g = np.reshape(a, (int(len(a) / width), width))
            g = np.uint8(g)

            fpng = self.out_path + file + ".png"
            imageio.imwrite(fpng, g)

            outfile = self.out_path + file + "_thumb.png"
            print(outfile)
            size = 256, 256

            if fpng != outfile:
                im = Image.open(fpng)
                im.thumbnail(size, Image.Resampling.LANCZOS)
                im.save(outfile, "PNG")

        except Exception as e:
            print(f"[ERROR] An error occurred while processing file {file}: {str(e)}")

    def get_all(self):
        path = self.in_path
        for file in os.listdir(path):
            self.get_image(path, file)

def main():
    mal_path = 'samples/malware_samples/'
    nor_path = 'samples/normal_samples/'

    mal_out_path = 'images/malware/'
    nor_out_path = 'images/normal/'

    im1 = IMAGE_feature(mal_path, mal_out_path)
    im1.get_all()

    im2 = IMAGE_feature(nor_path, nor_out_path)
    im2.get_all()

if __name__ == '__main__':
    main()

