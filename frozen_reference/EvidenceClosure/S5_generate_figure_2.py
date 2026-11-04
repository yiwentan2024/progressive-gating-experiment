"""Generate Figure 2 as a high-resolution, print-readable contract diagram."""
import argparse
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont


HERE = Path(__file__).parent
W, H = 2600, 1650
BG, INK, BLUE, GREEN, RED = "#ffffff", "#243746", "#dce8f0", "#e1efe8", "#f6e3df"


def font(size, bold=False):
    candidates = (["DejaVuSans-Bold.ttf", "arialbd.ttf"] if bold else ["DejaVuSans.ttf", "arial.ttf"])
    for name in candidates:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    raise RuntimeError("No DejaVu Sans or Arial TrueType font was found")


F_TITLE, F_PANEL, F_NODE, F_SMALL = font(44, True), font(34, True), font(29, True), font(24)
image = Image.new("RGB", (W, H), BG); draw = ImageDraw.Draw(image)


def box(x, y, w, h, title, subtitle="", fill=BLUE):
    draw.rounded_rectangle((x, y, x+w, y+h), radius=18, fill=fill, outline="#527083", width=4)
    lines = [title] + ([subtitle] if subtitle else [])
    total = sum(draw.textbbox((0,0), line, font=F_NODE if i==0 else F_SMALL)[3] for i,line in enumerate(lines)) + 8*(len(lines)-1)
    yy = y + (h-total)/2
    for i,line in enumerate(lines):
        f=F_NODE if i==0 else F_SMALL; bb=draw.textbbox((0,0),line,font=f); draw.text((x+(w-(bb[2]-bb[0]))/2,yy),line,font=f,fill=INK); yy += bb[3]-bb[1]+8


def arrow(points, label="", dashed=False):
    width=5
    if dashed:
        for a,b in zip(points[:-1],points[1:]):
            dx,dy=b[0]-a[0],b[1]-a[1]; length=max(abs(dx),abs(dy)); steps=max(1,int(length/24))
            for i in range(0,steps,2):
                p=(a[0]+dx*i/steps,a[1]+dy*i/steps); q=(a[0]+dx*min(i+1,steps)/steps,a[1]+dy*min(i+1,steps)/steps); draw.line((p,q),fill="#527083",width=width)
    else: draw.line(points,fill="#527083",width=width,joint="curve")
    a,b=points[-2],points[-1]; dx,dy=b[0]-a[0],b[1]-a[1]
    if abs(dx)>=abs(dy): head=[b,(b[0]-18*(1 if dx>0 else -1),b[1]-10),(b[0]-18*(1 if dx>0 else -1),b[1]+10)]
    else: head=[b,(b[0]-10,b[1]-18*(1 if dy>0 else -1)),(b[0]+10,b[1]-18*(1 if dy>0 else -1))]
    draw.polygon(head,fill="#527083")
    if label:
        segments=list(zip(points[:-1],points[1:])); a0,b0=max(segments,key=lambda pair:(pair[1][0]-pair[0][0])**2+(pair[1][1]-pair[0][1])**2)
        mid=((a0[0]+b0[0])/2,(a0[1]+b0[1])/2); bb=draw.textbbox((0,0),label,font=F_SMALL); tw=bb[2]-bb[0]
        tx=mid[0]-tw/2; ty=mid[1]-34
        draw.rectangle((tx-8,ty-3,tx+tw+8,ty+31),fill=BG); draw.text((tx,ty),label,font=F_SMALL,fill="#315f7a")


draw.rounded_rectangle((25,25,W-25,1120),radius=22,outline="#8ba3b2",width=4)
draw.text((55,45),"(a) Canonical evidence graph and mandatory row–edge agreement",font=F_PANEL,fill="#315f7a")
# Nodes
box(80,150,330,135,"Requirement","accepted WorkItem")
box(520,150,300,135,"Change","reviewed")
box(930,150,300,135,"Build","selected + successful")
box(1340,150,320,135,"TestRun","selected + mandatory")
box(930,390,300,135,"Artifact","selected + immutable")
box(1340,390,360,135,"ReleaseDecision","manifest + policy",GREEN)
box(1860,390,330,135,"Deployment","environment + time",GREEN)
box(520,690,340,135,"GateEvaluation","mode + phase + decision")
box(80,690,320,135,"Exception","issue + expiry + revoke")
box(1340,690,320,135,"Candidate signal","real signal; admit + decide")
box(1810,690,300,135,"Incident","attributed candidate only")
box(1340,900,470,130,"Collection attestation","zero or N; batch + count + digest")
box(930,690,300,135,"Finding","existing / later req.")
# Main lineage
arrow([(520,218),(410,218)],"implements")
arrow([(820,218),(930,218)],"triggers")
arrow([(1230,218),(1340,218)],"evaluated_by")
arrow([(1080,285),(1080,390)],"produces")
arrow([(1340,458),(1230,458)],"approves")
arrow([(1520,390),(1520,330),(670,330),(670,285)],"includes_change")
arrow([(1860,458),(1700,458)],"executes")
# Evidence-row consistency edges
arrow([(400,758),(520,758)],"authorizes")
arrow([(690,690),(690,610),(1080,610),(1080,525)],"evaluates",True)
arrow([(1660,758),(1810,758)],"if attributed")
arrow([(1960,690),(1960,610),(2025,610),(2025,525)],"attributed_to")
arrow([(1960,825),(1960,870),(1080,870),(1080,825)])
draw.text((1110,838),"creates_finding",font=F_SMALL,fill="#315f7a")
arrow([(1575,900),(1575,825)])
draw.text((1590,838),"count + digest",font=F_SMALL,fill="#315f7a")
arrow([(930,825),(900,900),(450,900),(450,350),(185,350),(185,285)],"relates / creates req.",True)
draw.text((1840,920),"Zero candidates are valid only with\na complete collection attestation.",font=F_SMALL,fill="#7a3d34")

# Snapshot state machine panel
draw.rounded_rectangle((25,1150,W-25,H-25),radius=22,outline="#8ba3b2",width=4)
draw.text((55,1170),"(b) Immutable snapshots and reopening after late evidence or candidate admission",font=F_PANEL,fill="#315f7a")
box(90,1280,420,190,"Snapshot n","closed_as_of(t_eval); immutable",GREEN)
box(760,1280,570,190,"Later evidence","opened / reported / attributed\nrecorded as distinct times",RED)
box(1580,1280,470,190,"Snapshot n+1","supersedes n; recomputed",GREEN)
arrow([(510,1375),(760,1375)],"after evaluated_at(n)")
arrow([(1330,1375),(1580,1375)],"reopen + supersede")
draw.rounded_rectangle((2110,1260,2525,1495),radius=18,fill=BLUE,outline="#527083",width=4)
rules=["At most one successor","Exactly one if reopening","Strictly increasing time","Late admitted evidence","cannot rewrite history"]
yy=1290
for rule in rules: draw.text((2140,yy),"–"+rule,font=F_SMALL,fill=INK); yy+=39
draw.text((70,1575),"Contract core: selected path →policy-bound gates →collection attestation + real candidates →Requirement lifecycle →cutoff-safe closed_as_of",font=F_SMALL,fill=INK)

parser=argparse.ArgumentParser(description="Generate the Figure 2 contract diagram.")
parser.add_argument("--output",default=str(HERE/"reproduced"/"figure_2.png"),help="output path; defaults outside frozen evidence files")
args=parser.parse_args()
output=Path(args.output); output.parent.mkdir(parents=True,exist_ok=True)
image.save(output,dpi=(300,300),optimize=True)
print(output)


