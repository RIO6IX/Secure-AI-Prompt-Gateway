"""Draw the extension icons (16/32/48/128 px) with Pillow.

    python scripts/make_icons.py

A white shield with a keyhole on a blue rounded square, drawn at 512 px and
downscaled so the small sizes stay smooth.
"""

from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
BLUE = (37, 99, 235, 255)
NAVY = (15, 29, 53, 255)
WHITE = (255, 255, 255, 255)


def draw(size: int = 512) -> Image.Image:
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    pen = ImageDraw.Draw(image)
    pen.rounded_rectangle((0, 0, size - 1, size - 1), radius=size // 5, fill=BLUE)
    # shield
    s = size / 512
    shield = [(256, 70), (410, 125), (400, 270), (256, 450), (112, 270), (102, 125)]
    pen.polygon([(x * s, y * s) for x, y in shield], fill=WHITE)
    # keyhole
    pen.ellipse((216 * s, 175 * s, 296 * s, 255 * s), fill=NAVY)
    pen.polygon([(238 * s, 240 * s), (274 * s, 240 * s), (286 * s, 340 * s), (226 * s, 340 * s)], fill=NAVY)
    return image


def main() -> None:
    out = ROOT / "icons"
    out.mkdir(exist_ok=True)
    master = draw()
    for size in (16, 32, 48, 128):
        master.resize((size, size), Image.LANCZOS).save(out / f"icon-{size}.png", optimize=True)
        print(f"icons/icon-{size}.png")


if __name__ == "__main__":
    main()
