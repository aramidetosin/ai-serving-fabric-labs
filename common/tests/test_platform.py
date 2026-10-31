"""Tests for platform/dell-sonic-4.6.0: the two copies of vrnetlab's launcher, the patch that turns
one into the other, and the vrnetlab pin in spec/versions.yaml that both name. Then
platform/paloalto-pa-vm-12.1.2, the PA-VM's launcher, and images/VENDOR-IMAGES.md, which gives
every vendor image the labs name its tag, its vrnetlab pin and the labs that run it."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PLAT = ROOT / "platform" / "dell-sonic-4.6.0"
BASE = PLAT / "launch.py.upstream-plus-numnics"
PATCHED = PLAT / "launch.py.patched"
PATCH = PLAT / "patch_launch.py"
NOTICE = PLAT / "LICENSE.vrnetlab"
LAUNCHER = "dell/dell_sonic/docker/launch.py"
REPO = "https://github.com/srl-labs/vrnetlab"
NUMNICS = '        self.num_nics = int(os.getenv("NUM_NICS", "10"))\n'
FIXED = "        self.num_nics = 10\n"
PAN = ROOT / "platform" / "paloalto-pa-vm-12.1.2"
PAN_PATCHED = PAN / "launch.py.patched"
PAN_NOTICE = PAN / "LICENSE.vrnetlab"
PAN_LAUNCHER = "paloalto/pan/docker/launch.py"
VENDOR = ROOT / "images" / "VENDOR-IMAGES.md"
BOOT = ROOT / "common" / "stages" / "boot.sh"
# The patched PA-VM launcher logs this line when its own commit of the XML finishes; the boot stage
# looks for it with OK after it before it falls back to fw-startup.py (FRAMEWORK.md 3.3).
COMMIT_LINE = "XML startup config commit finished: result="
VENDOR_KEYS = {"dell_sonic": LAUNCHER, "pa_vm": PAN_LAUNCHER,
               "truenas": "truenas/truenas/docker/launch.py", "ontap": "netapp/ontap/docker/launch.py"}
# Every lab, found as the top Makefile finds them: a chapter.yaml in chNN/ or dev/<milestone>/.
LABS = tuple(sorted(p.parent.relative_to(ROOT).as_posix()
                    for p in [*ROOT.glob("ch[0-9][0-9]/chapter.yaml"), *ROOT.glob("dev/*/chapter.yaml")]))


def have_yaml() -> bool:
    try:
        import yaml  # noqa: F401
    except ImportError:
        return False
    return True


def images() -> dict:
    import yaml
    return yaml.safe_load((ROOT / "spec" / "versions.yaml").read_text())["images"]


def pin(key: str = "dell_sonic") -> dict:
    return images()[key]["vrnetlab"]


def header(path: Path) -> str:
    """The comment block under a launcher's shebang, as one line."""
    out = []
    for ln in path.read_text().splitlines()[1:]:
        if not is_comment(ln):
            break
        out.append(ln)
    return " ".join(out)


def blob(text: str) -> str:
    """The git blob id of a file holding text, as git hash-object prints it."""
    data = text.encode()
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def is_comment(line: str) -> bool:
    return line.lstrip().startswith("#")


def stock(text: str) -> str:
    """vrnetlab's own launcher, from launch.py.upstream-plus-numnics: take out the comment block under
    the shebang and the comments above DEFAULT_PASSWORD and the NUM_NICS line, and put the fixed
    count back. Anything else the copy changed stays, so the blob no longer matches the pin."""
    lines = text.splitlines(keepends=True)
    end = 1
    while is_comment(lines[end]):
        end += 1
    lines = lines[:1] + lines[end:]
    out = []
    for line in lines:
        if line.startswith("DEFAULT_PASSWORD = ") or line == NUMNICS:
            while out and is_comment(out[-1]):
                out.pop()
        out.append(FIXED if line == NUMNICS else line)
    return "".join(out)


def patched(text: str, tmp: Path) -> str:
    f = tmp / "launch.py"
    f.write_text(text)
    subprocess.run([sys.executable, "-I", str(PATCH), str(f)], check=True, capture_output=True)
    return f.read_text()


class PlatformLauncherTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_patch_turns_the_starting_point_into_the_result(self):
        self.assertEqual(patched(BASE.read_text(), self.d), PATCHED.read_text())

    @unittest.skipUnless(have_yaml(), "needs PyYAML")
    def test_starting_point_is_the_pinned_launcher_plus_numnics(self):
        base = BASE.read_text()
        self.assertEqual(base.count(NUMNICS), 1)
        self.assertNotIn(FIXED, base)
        self.assertEqual(blob(stock(base)), pin()["blobs"][LAUNCHER])

    def test_patch_accepts_the_stock_launcher(self):
        # Patched from vrnetlab's own file, the result differs from launch.py.patched only in comments.
        got = patched(stock(BASE.read_text()), self.d)
        self.assertIn(NUMNICS, got)
        strip = lambda t: [ln for ln in t.splitlines() if not is_comment(ln)]  # noqa: E731
        self.assertEqual(strip(got), strip(PATCHED.read_text()))

    @unittest.skipUnless(have_yaml(), "needs PyYAML")
    def test_both_copies_name_their_source_and_notice(self):
        p = pin()
        self.assertEqual(p["repository"], REPO)
        self.assertRegex(p["commit"], r"^[0-9a-f]{40}$")
        for f in (BASE, PATCHED):
            lines = f.read_text().splitlines()
            head = []
            for ln in lines[1:]:
                if not is_comment(ln):
                    break
                head.append(ln)
            text = " ".join(head)
            for want in (REPO, LAUNCHER, p["commit"], "LICENSE.vrnetlab", "MIT License"):
                self.assertIn(want, text, f"{f.name}: header names {want}")
        readme = (PLAT / "README.md").read_text()
        self.assertIn(p["commit"], readme)
        self.assertIn(p["blobs"][LAUNCHER], readme)

    def test_factory_default_login_keeps_its_comment(self):
        # the literal is the image's published factory default, and says so where it stands
        for f in (BASE, PATCHED):
            lines = f.read_text().splitlines()
            at = next(i for i, ln in enumerate(lines) if ln.startswith("DEFAULT_PASSWORD = "))
            block = []
            i = at - 1
            while i >= 0 and is_comment(lines[i]):
                block.insert(0, lines[i])
                i -= 1
            self.assertTrue(block, f"{f.name}: a comment right above DEFAULT_PASSWORD")
            text = " ".join(block)
            self.assertIn("factory-default login", text, f.name)
            self.assertIn("knowledge base article 000218783", text, f.name)

    @unittest.skipUnless(have_yaml(), "needs PyYAML")
    def test_notice_is_vrnetlabs_mit_licence(self):
        text = NOTICE.read_text()
        for want in ("The MIT License (MIT)", "Copyright (c) 2016 Kristian Larsson",
                     "The above copyright notice and this permission notice shall be included in all\n"
                     "copies or substantial portions of the Software.",
                     REPO, pin()["commit"], BASE.name, PATCHED.name):
            self.assertIn(want, text)


class PaVmLauncherTest(unittest.TestCase):
    @unittest.skipUnless(have_yaml(), "needs PyYAML")
    def test_launcher_names_its_source_and_notice(self):
        p = pin("pa_vm")
        text = header(PAN_PATCHED)
        for want in (REPO, PAN_LAUNCHER, p["commit"], "LICENSE.vrnetlab", "MIT License"):
            self.assertIn(want, text, f"header names {want}")
        readme = (PAN / "README.md").read_text()
        self.assertIn(p["commit"], readme)
        self.assertIn(p["blobs"][PAN_LAUNCHER], readme)

    @unittest.skipUnless(have_yaml(), "needs PyYAML")
    def test_notice_is_vrnetlabs_mit_licence(self):
        text = PAN_NOTICE.read_text()
        for want in ("The MIT License (MIT)", "Copyright (c) 2016 Kristian Larsson",
                     "The above copyright notice and this permission notice shall be included in all\n"
                     "copies or substantial portions of the Software.",
                     REPO, pin("pa_vm")["commit"], PAN_PATCHED.name):
            self.assertIn(want, text)
        rule = "-" * 80 + "\n"
        body = lambda f: f.read_text().split(rule)[1]  # noqa: E731
        self.assertEqual(body(PAN_NOTICE), body(NOTICE))

    def test_launcher_logs_the_line_the_boot_stage_waits_for(self):
        self.assertIn(f'"{COMMIT_LINE}%s"', PAN_PATCHED.read_text())
        self.assertIn(f"{COMMIT_LINE}OK", BOOT.read_text())

    def test_launcher_is_python(self):
        compile(PAN_PATCHED.read_text(), str(PAN_PATCHED), "exec")

    def test_command_line_defaults_keep_their_comment(self):
        # the login defaults are vrnetlab's own, and the kind's command line replaces them
        lines = PAN_PATCHED.read_text().splitlines()
        at = next(i for i, ln in enumerate(lines) if ln.startswith('    parser.add_argument("--hostname", '))
        self.assertTrue(lines[at + 1].startswith('    parser.add_argument("--username", '))
        self.assertTrue(lines[at + 2].startswith('    parser.add_argument("--password", '))
        block = []
        i = at - 1
        while i >= 0 and is_comment(lines[i]):
            block.insert(0, lines[i])
            i -= 1
        text = " ".join(block)
        for want in ("vrnetlab's own defaults, unchanged", "paloalto_panos", "command line"):
            self.assertIn(want, text)


# The switch vendor's full product name stays only in the vendor's own file names, document titles
# and links, which a reader needs verbatim; elsewhere the repository says SONiC 4.6.0.
PRODUCT_RX = re.compile(r"(?i)enterprise[ _-]?sonic|sonic[ _-]?enterprise|sonic-os-[0-9.]+-enterprise")
PRODUCT_KEPT = ("Enterprise_SONiC_OS_4.6.0_gns3.zip", "Enterprise_SONiC_OS_4.6.0.img", "SONiC-OS-4.6.0-Enterprise_Base",
                '"PowerSwitch: Enterprise SONiC: Getting Started and Basics Guide"')


class ProductNameTest(unittest.TestCase):
    def test_full_product_name_only_in_file_names_and_titles(self):
        me = Path(__file__).resolve()
        sys.path.insert(0, str(me.parent))
        import codefiles  # noqa: PLC0415
        for p in codefiles.files(ROOT, (".git", "audits", "__pycache__")):
            rel = p.relative_to(ROOT)
            if p.resolve() == me:
                continue
            try:
                text = p.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            if not PRODUCT_RX.search(text):
                continue
            for no, line in enumerate(text.splitlines(), 1):
                for kept in PRODUCT_KEPT:
                    line = line.replace(kept, "")
                line = re.sub(r"https?://\S+", "", line)  # a document's link spells its title
                with self.subTest(path=f"{rel.as_posix()}:{no}"):
                    self.assertIsNone(PRODUCT_RX.search(line))


class VendorImagesTest(unittest.TestCase):
    @unittest.skipUnless(have_yaml(), "needs PyYAML")
    def test_every_vendor_image_is_pinned_and_on_the_page(self):
        imgs, page = images(), VENDOR.read_text()
        for key, launcher in VENDOR_KEYS.items():
            with self.subTest(image=key):
                v = imgs[key]["vrnetlab"]
                self.assertEqual(v["repository"], REPO)
                for c in (v["commit"], v.get("common_commit", v["commit"])):
                    self.assertRegex(c, r"^[0-9a-f]{40}$")
                    self.assertIn(c[:12], page)
                for path in (launcher, "common/vrnetlab.py", "common/healthcheck.py"):
                    self.assertRegex(v["blobs"].get(path, ""), r"^[0-9a-f]{40}$", path)
                self.assertIn(f"`{imgs[key]['ref']}`", page)

    @unittest.skipUnless(have_yaml(), "needs PyYAML")
    def test_every_vrnetlab_image_a_lab_names_is_a_vendor_image(self):
        import yaml
        refs = {imgs["ref"] for k, imgs in images().items() if k in VENDOR_KEYS}
        for lab in LABS:
            topo = yaml.safe_load((ROOT / lab / "topo.clab.yml").read_text())
            for name, node in topo["topology"]["nodes"].items():
                if str(node.get("image", "")).startswith("vrnetlab/"):
                    self.assertIn(node["image"], refs, f"{lab} {name}")

    @unittest.skipUnless(have_yaml(), "needs PyYAML")
    def test_each_vendor_image_names_the_labs_whose_inventory_runs_it(self):
        """The page table's Labs column against the images each lab's gen/inventory.json names. A
        cell reads "every lab", or "every lab but `x` (...)" listing every other lab, or else names
        exactly the labs that run the image, none for an image no lab runs yet."""
        runs: dict[str, set[str]] = {}
        for lab in LABS:
            for ref in json.loads((ROOT / lab / "gen" / "inventory.json").read_text())["images"]:
                runs.setdefault(ref, set()).add(lab)
        rows = {}
        for line in VENDOR.read_text().splitlines():
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            tag = re.match(r"`(vrnetlab/[^`]+)`", cells[1]) if len(cells) == 5 else None
            if tag:
                rows[tag.group(1)] = cells[4]
        self.assertEqual(set(rows), {imgs["ref"] for k, imgs in images().items() if k in VENDOR_KEYS})
        for ref, cell in rows.items():
            with self.subTest(image=ref):
                but = re.fullmatch(r"every lab but `([^`]+)` \((.+)\)", cell)
                if cell == "every lab":
                    named = set(LABS)
                elif but:
                    named = set(re.findall(r"`([^`]+)`", but.group(2)))
                    self.assertEqual(named, set(LABS) - {but.group(1)}, cell)
                    self.assertIn(but.group(1), LABS, cell)
                else:
                    named = set(re.findall(r"`([^`]+)`", cell))
                self.assertEqual(named, runs.get(ref, set()), cell)


if __name__ == "__main__":
    unittest.main()
