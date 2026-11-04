"""Generate Figure 4: computable gate evidence and authority validation."""
import argparse
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


HERE = Path(__file__).parent
W, H = 2200, 1260
BG = "#ffffff"
BLUE = "#dce8ef"
GREEN = "#e3f0e7"
AMBER = "#f6ead6"
RED = "#f3dddd"
INK = "#263640"
LINE = "#6b8797"


def font(size, bold=False):
    candidates = [
        Path(r"C:\Windows\Fonts\arialbd.ttf" if bold else r"C:\Windows\Fonts\arial.ttf"),
        Path(r"C:\Windows\Fonts\calibrib.ttf" if bold else r"C:\Windows\Fonts\calibri.ttf"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return ImageFont.truetype(str(candidate), size)
    return ImageFont.load_default()


TITLE = font(44, True)
LABEL = font(32, True)
BODY = font(30)
SMALL = font(27)


def wrapped(draw, xy, text, width, font_obj, fill=INK, anchor="mm", spacing=6):
    words = text.split()
    lines, current = [], ""
    for word in words:
        trial = f"{current} {word}".strip()
        if draw.textbbox((0, 0), trial, font=font_obj)[2] <= width:
            current = trial
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    draw.multiline_text(xy, "\n".join(lines), font=font_obj, fill=fill, anchor=anchor, align="center", spacing=spacing)


def box(draw, x, y, w, h, title, text, fill):
    draw.rounded_rectangle((x, y, x + w, y + h), radius=18, fill=fill, outline=LINE, width=3)
    draw.text((x + w / 2, y + 35), title, font=LABEL, fill=INK, anchor="mm")
    wrapped(draw, (x + w / 2, y + h / 2 + 26), text, w - 48, BODY)


def arrow(draw, x1, y1, x2, y2):
    draw.line((x1, y1, x2, y2), fill=LINE, width=5)
    direction = 1 if x2 >= x1 else -1
    draw.polygon([(x2, y2), (x2 - 18 * direction, y2 - 12), (x2 - 18 * direction, y2 + 12)], fill=LINE)


image = Image.new("RGB", (W, H), BG)
draw = ImageDraw.Draw(image)
draw.text((W / 2, 48), "Executable Gate-Evidence and Authority Contract", font=TITLE, fill=INK, anchor="mm")

draw.text((55, 115), "(a) Computable gate decision", font=LABEL, fill=INK)
boxes = [
    (55, 165, 380, 230, "S4 policy", "owner, operator family, value type, unit, effective interval", BLUE),
    (485, 165, 430, 230, "Gate record", "owner, operator, threshold, observation, unit, declared decision", BLUE),
    (965, 165, 370, 230, "Validator", "trim and type checks; recompute eq/ne/lt/le/gt/ge/in", GREEN),
    (1385, 165, 350, 230, "Comparison", "computed outcome must agree with pass, fail, or exception", GREEN),
    (1785, 165, 360, 230, "Stable result", "close or emit named failure code; invalid input suppresses metrics", AMBER),
]
for args in boxes:
    box(draw, *args)
for left, right in zip(boxes, boxes[1:]):
    arrow(draw, left[0] + left[2], left[1] + left[3] / 2, right[0], right[1] + right[3] / 2)

draw.text((55, 455), "(b) Gate-owner authorization", font=LABEL, fill=INK)
box(draw, 55, 505, 500, 210, "Effective policy owner", "direct equality is accepted", BLUE)
box(draw, 650, 505, 560, 210, "Delegation registry", "exact policy-gate key; gate owner; service scope; interval; controlled wildcard", GREEN)
box(draw, 1305, 505, 400, 210, "Owner check", "retry preserves owner; owner change requires a new gate episode or policy transition", GREEN)
box(draw, 1800, 505, 345, 210, "Failure", "owner mismatch or unauthorized owner", RED)
arrow(draw, 555, 610, 650, 610)
arrow(draw, 1210, 610, 1305, 610)
arrow(draw, 1705, 610, 1800, 610)

draw.text((55, 775), "(c) Exception authorization at decision time", font=LABEL, fill=INK)
box(draw, 55, 825, 470, 240, "Exception record", "approver, rationale, gate scope, service scope, risk class, issue/expiry/revocation", BLUE)
box(draw, 620, 825, 510, 240, "Authority registry", "subject/role, policy, gate/service scope, risk ceiling, effective/retired interval", BLUE)
box(draw, 1225, 825, 430, 240, "Authorization check", "waiver allowed + complete record + exact policy-gate + time/scope/risk", GREEN)
box(draw, 1750, 825, 395, 240, "EIR and closure", "empty, expired, revoked, scoped-mismatch, or unauthorized exceptions are invalid", AMBER)
arrow(draw, 525, 945, 620, 945)
arrow(draw, 1130, 945, 1225, 945)
arrow(draw, 1655, 945, 1750, 945)

draw.rounded_rectangle((55, 1125, 2145, 1210), radius=14, fill="#eef2f4", outline=LINE, width=2)
wrapped(draw, (1100, 1168), "S1 is executable metadata: column_required, value_required, nullable_when, type, vocabulary/range, referential rule, and stable failure code.", 1980, SMALL)

parser = argparse.ArgumentParser()
parser.add_argument("--output", default=str(HERE / "S5_figures" / "figure_4.png"))
args = parser.parse_args()
output = Path(args.output)
output.parent.mkdir(parents=True, exist_ok=True)
image.save(output, dpi=(240, 240))
print(output)
