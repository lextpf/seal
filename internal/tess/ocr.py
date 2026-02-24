import sys
import struct
import os
import warnings
import numpy as np
import cv2
import easyocr
import torch

DEBUG_PREPASS = False
DEBUG_OCR_LOG = False
FAST_MODE = True
MAX_INPUT_SIDE = 960
EASYOCR_BEAM_WIDTH = 10
REC_PIPELINE_BONUS = 0.45
ALLOWLIST = "ACDEFHJKMNPRTUVWXYacdefhjkmnprtuvwxy34679!#$%&*+-=._:@^~"

warnings.filterwarnings(
    "ignore",
    message=r".*pin_memory.*no accelerator is found.*",
    category=UserWarning,
)
warnings.filterwarnings(
    "ignore",
    message=r".*overflow encountered in scalar add.*",
    category=RuntimeWarning,
)


def env_flag_enabled(key):
    raw = os.getenv(key)
    if raw is None:
        return False
    return raw.strip().lower() in ("1", "true", "yes", "on")


def env_flag_default_on(key):
    raw = os.getenv(key)
    if raw is None:
        return True
    return raw.strip().lower() in ("1", "true", "yes", "on")


def env_int_or_default(key, default, min_val, max_val):
    raw = os.getenv(key)
    if raw is None:
        return default
    try:
        value = int(raw.strip())
    except Exception:
        return default
    if value < min_val:
        value = min_val
    if value > max_val:
        value = max_val
    return value


def choose_gpu_mode():
    # Backward-compatible switch: force GPU if requested explicitly.
    if env_flag_enabled("TESS_OCR_FORCE_GPU"):
        return True, "gpu (forced)"

    # Safer default for system stability: do not touch CUDA unless opted in.
    mode = os.getenv("TESS_OCR_BACKEND", "cpu").strip().lower()
    if mode in ("gpu", "cuda"):
        return True, "gpu"
    if mode == "auto":
        return bool(torch.cuda.is_available()), "auto"

    # cpu / unknown -> CPU fallback
    return False, "cpu"


def order_quad_points(pts):
    pts = np.array(pts, dtype=np.float32).reshape(4, 2)
    s = pts.sum(axis=1)
    d = np.diff(pts, axis=1).reshape(-1)
    tl = pts[np.argmin(s)]
    br = pts[np.argmax(s)]
    tr = pts[np.argmin(d)]
    bl = pts[np.argmax(d)]
    return np.array([tl, tr, br, bl], dtype=np.float32)


def scale_quad(quad, scale, img_w, img_h):
    quad = np.array(quad, dtype=np.float32).reshape(4, 2)
    if abs(scale - 1.0) < 1e-6:
        return quad
    center = np.mean(quad, axis=0, keepdims=True)
    scaled = (quad - center) * float(scale) + center
    scaled[:, 0] = np.clip(scaled[:, 0], 0, max(0, img_w - 1))
    scaled[:, 1] = np.clip(scaled[:, 1], 0, max(0, img_h - 1))
    return scaled.astype(np.float32)


def quad_to_bbox(quad, img_w, img_h):
    xs = quad[:, 0]
    ys = quad[:, 1]
    x0 = max(0, int(np.floor(np.min(xs))))
    y0 = max(0, int(np.floor(np.min(ys))))
    x1 = min(img_w, int(np.ceil(np.max(xs))) + 1)
    y1 = min(img_h, int(np.ceil(np.max(ys))) + 1)
    return (x0, y0, x1, y1)


def warp_perspective_quad(img, quad):
    quad = order_quad_points(quad)
    width_a = np.linalg.norm(quad[2] - quad[3])
    width_b = np.linalg.norm(quad[1] - quad[0])
    height_a = np.linalg.norm(quad[1] - quad[2])
    height_b = np.linalg.norm(quad[0] - quad[3])

    out_w = int(round(max(width_a, width_b)))
    out_h = int(round(max(height_a, height_b)))
    if out_w < 40 or out_h < 40:
        return None

    dst = np.array(
        [[0, 0], [out_w - 1, 0], [out_w - 1, out_h - 1], [0, out_h - 1]],
        dtype=np.float32,
    )
    mat = cv2.getPerspectiveTransform(quad.astype(np.float32), dst)
    return cv2.warpPerspective(
        img, mat, (out_w, out_h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE
    )


def detect_phone_screen_roi(img, warp_source=None):
    h, w = img.shape[:2]
    if h < 80 or w < 80:
        return None

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    gray = cv2.GaussianBlur(gray, (5, 5), 0)

    # Detect dark display-like panel around center (portrait or landscape).
    dark_thr = int(np.clip(np.percentile(gray, 38), 45, 100))
    dark = np.zeros_like(gray, dtype=np.uint8)
    dark[gray < dark_thr] = 255
    dark = cv2.morphologyEx(
        dark, cv2.MORPH_CLOSE, cv2.getStructuringElement(cv2.MORPH_RECT, (9, 9)), iterations=2
    )
    dark = cv2.morphologyEx(
        dark, cv2.MORPH_OPEN, cv2.getStructuringElement(cv2.MORPH_RECT, (5, 5)), iterations=1
    )

    contours, _ = cv2.findContours(dark, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    if not contours:
        return None

    frame_area = float(h * w)
    cx_frame = w * 0.5
    cy_frame = h * 0.52
    best = None

    for cnt in contours:
        contour_area = float(cv2.contourArea(cnt))
        if contour_area < frame_area * 0.02:
            continue

        rect = cv2.minAreaRect(cnt)
        rw, rh = rect[1]
        if rw < 2.0 or rh < 2.0:
            continue
        rect_area = float(rw * rh)
        if rect_area < frame_area * 0.02:
            continue
        ar = max(rw, rh) / max(1.0, min(rw, rh))
        # Accept both portrait and landscape phone screens.
        if ar > 3.4:
            continue
        if max(rw / float(w), rh / float(h)) < 0.26:
            continue
        fill_ratio = contour_area / max(1.0, rect_area)
        if fill_ratio < 0.38:
            continue

        quad = order_quad_points(cv2.boxPoints(rect))
        qx0, qy0, qx1, qy1 = quad_to_bbox(quad, w, h)
        cw = qx1 - qx0
        ch = qy1 - qy0
        cx = qx0 + cw * 0.5
        cy = qy0 + ch * 0.5
        center_bonus = max(0.0, 1.0 - abs(cx - cx_frame) / max(1.0, w * 0.5)) * 0.7
        center_bonus += max(0.0, 1.0 - abs(cy - cy_frame) / max(1.0, h * 0.5)) * 0.55
        size_bonus = min(1.0, rw / float(w)) * 0.45 + min(1.0, rh / float(h)) * 0.45
        score = contour_area * (1.0 + center_bonus + size_bonus) + rect_area * 0.15
        if best is None or score > best[0]:
            best = (score, quad)

    if best is None:
        return None

    _, quad = best
    quad = scale_quad(quad, 1.03, w, h)
    bbox = quad_to_bbox(quad, w, h)
    source = warp_source if warp_source is not None else img
    warped = warp_perspective_quad(source, quad)
    if warped is None:
        x0, y0, x1, y1 = bbox
        if x1 - x0 < 8 or y1 - y0 < 8:
            return None
        warped = source[y0:y1, x0:x1]
    return {"bbox": bbox, "quad": quad, "warped": warped}


def is_good_candidate(results, combined):
    if not combined:
        return False
    conf = candidate_confidence(results)
    if conf >= 0.65 and len(combined) >= 14:
        return True
    if has_strong_result(results) and len(combined) >= 14:
        return True
    return False


def downscale_for_speed(img):
    h, w = img.shape[:2]
    max_side = max(h, w)
    if max_side <= MAX_INPUT_SIDE:
        return img
    scale = MAX_INPUT_SIDE / float(max_side)
    return cv2.resize(img, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA)


def build_text_mask(gray):
    # Combine global+local thresholding while suppressing broad background regions.
    _, mask_global = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    mask_local = cv2.adaptiveThreshold(
        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, blockSize=31, C=-2
    )
    mask = cv2.bitwise_and(mask_global, mask_local)
    mask = cv2.morphologyEx(
        mask, cv2.MORPH_OPEN, cv2.getStructuringElement(cv2.MORPH_RECT, (2, 2)), iterations=1
    )
    return mask


_gamma_lut_cache = {}


def apply_gamma_correction(bgr_crop):
    gray = cv2.cvtColor(bgr_crop, cv2.COLOR_BGR2GRAY)
    mean_lum = float(np.mean(gray))
    if mean_lum < 80:
        gamma = 0.75
    elif mean_lum < 120:
        gamma = 0.85
    elif mean_lum > 200:
        gamma = 1.3
    elif mean_lum > 160:
        gamma = 1.15
    else:
        return bgr_crop
    if gamma not in _gamma_lut_cache:
        inv = 1.0 / gamma
        _gamma_lut_cache[gamma] = np.array(
            [min(255, int((i / 255.0) ** inv * 255.0)) for i in range(256)],
            dtype=np.uint8,
        )
    return cv2.LUT(bgr_crop, _gamma_lut_cache[gamma])


def tighten_text_band(mask, roi):
    x0, y0, x1, y1 = roi
    if x1 - x0 < 8 or y1 - y0 < 8:
        return roi
    sub = mask[y0:y1, x0:x1]
    if sub.size == 0:
        return roi
    row_hits = np.count_nonzero(sub, axis=1)
    if row_hits.size == 0:
        return roi
    peak = int(np.max(row_hits))
    if peak <= 0:
        return roi
    thresh = max(2, int(peak * 0.20))
    keep = np.where(row_hits >= thresh)[0]
    if keep.size == 0:
        return roi

    band_top = int(keep[0])
    band_bottom = int(keep[-1])
    band_h = max(1, band_bottom - band_top + 1)
    pad = max(3, int(band_h * 0.35))
    ny0 = max(0, y0 + band_top - pad)
    ny1 = min(mask.shape[0], y0 + band_bottom + 1 + pad)

    min_h = max(8, int((y1 - y0) * 0.45))
    cur_h = ny1 - ny0
    if cur_h < min_h:
        extra = (min_h - cur_h) // 2
        ny0 = max(0, ny0 - extra)
        ny1 = min(mask.shape[0], ny1 + (min_h - (ny1 - ny0)))
    return (x0, ny0, x1, ny1)


def find_text_roi(mask):
    h, w = mask.shape[:2]
    if h == 0 or w == 0:
        return None

    # Aggressively connect characters into line blobs — wide kernel bridges gaps
    # between separated chars (e.g. "T" far from "3*1-B...").
    linked = cv2.morphologyEx(
        mask, cv2.MORPH_CLOSE, cv2.getStructuringElement(cv2.MORPH_RECT, (45, 7)), iterations=1
    )
    contours, _ = cv2.findContours(linked, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    if not contours:
        return None

    frame_area = float(h * w)
    cx_frame = w * 0.5
    cy_frame = h * 0.65
    candidates = []

    for cnt in contours:
        x, y, cw, ch = cv2.boundingRect(cnt)
        area = float(cw * ch)
        if area > frame_area * 0.45:
            continue
        if area < frame_area * 0.0004:
            continue
        if cw < w * 0.03:
            continue
        if ch > h * 0.25:
            continue
        # Accept slightly non-wide blobs — single chars can be nearly square.
        if cw < ch * 0.8:
            continue

        # Prefer large line-like regions near lower center where phone text usually appears.
        cx = x + cw * 0.5
        cy = y + ch * 0.5
        dx = abs(cx - cx_frame) / max(1.0, w * 0.5)
        dy = abs(cy - cy_frame) / max(1.0, h * 0.65)
        center_bonus = max(0.0, 1.0 - 1.0 * dx - 0.85 * dy)
        score = area * (1.0 + center_bonus)
        candidates.append((score, x, y, cw, ch))

    if not candidates:
        return None

    candidates.sort(reverse=True, key=lambda v: v[0])
    _, ax, ay, aw, ah = candidates[0]

    # Merge ALL contours on the same text row — not just neighbors of the best.
    mx0, my0, mx1, my1 = ax, ay, ax + aw, ay + ah
    merged = True
    while merged:
        merged = False
        for _, x, y, cw, ch in candidates[1:]:
            if x >= mx0 and (x + cw) <= mx1 and y >= my0 and (y + ch) <= my1:
                continue  # already inside
            cy_a = (my0 + my1) * 0.5
            cy_b = y + ch * 0.5
            row_h = max(my1 - my0, ch)
            cy_dist = abs(cy_b - cy_a)
            y_overlap = min(my1, y + ch) - max(my0, y)
            if cy_dist <= row_h * 1.2 or y_overlap > 0:
                new_x0 = min(mx0, x)
                new_y0 = min(my0, y)
                new_x1 = max(mx1, x + cw)
                new_y1 = max(my1, y + ch)
                if (new_x0, new_y0, new_x1, new_y1) != (mx0, my0, mx1, my1):
                    mx0, my0, mx1, my1 = new_x0, new_y0, new_x1, new_y1
                    merged = True

    x, y, cw, ch = mx0, my0, (mx1 - mx0), (my1 - my0)
    # Keep context around the line, but avoid pulling too much UI chrome.
    pad_x = int(max(cw * 0.45, w * 0.08))
    pad_y = int(max(ch * 0.55, h * 0.035))
    # Detect if horizontal padding was clipped by frame boundaries.
    clipped = (x - pad_x < 0) or (x + cw + pad_x > w)
    x0 = max(0, x - pad_x)
    y0 = max(0, y - pad_y)
    x1 = min(w, x + cw + pad_x)
    y1 = min(h, y + ch + pad_y)

    # Ensure minimum ROI width for long tokens/symbol-heavy strings.
    min_w = int(w * 0.60)
    cur_w = x1 - x0
    if cur_w < min_w:
        extra = (min_w - cur_w) // 2
        x0 = max(0, x0 - extra)
        x1 = min(w, x1 + (min_w - (x1 - x0)))

    x0, y0, x1, y1 = tighten_text_band(mask, (x0, y0, x1, y1))
    return (x0, y0, x1, y1, clipped)


def is_bright_on_dark(gray_img):
    """Detect white/bright text on a dark/black background (e.g. phone screen)."""
    mean_lum = float(np.mean(gray_img))
    std_lum = float(np.std(gray_img))
    # Dark background with high contrast bright text.
    return mean_lum < 110 and std_lum > 40


def estimate_binary_speckle_ratio(bin_img):
    fg = int(cv2.countNonZero(bin_img))
    if fg <= 0:
        return 0.0
    n_labels, _, stats, _ = cv2.connectedComponentsWithStats(bin_img, connectivity=8)
    if n_labels <= 1:
        return 0.0
    tiny_area = 0
    for idx in range(1, n_labels):
        area = int(stats[idx, cv2.CC_STAT_AREA])
        if area <= 4:
            tiny_area += area
    return tiny_area / float(max(1, fg))


def build_ocr_inputs(crop_bgr, scale_override=None):
    crop_bgr = apply_gamma_correction(crop_bgr)
    pre_gray = cv2.cvtColor(crop_bgr, cv2.COLOR_BGR2GRAY)
    bright_on_dark = is_bright_on_dark(pre_gray)

    # Scale can be overridden by caller for recovery passes.
    scale = float(scale_override) if scale_override is not None else (3.0 if bright_on_dark else 2.0)
    crop = cv2.resize(crop_bgr, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
    raw_gray = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY)

    if bright_on_dark:
        # Edge-preserving denoise: bilateral filter keeps character edges sharp
        # (fastNlMeansDenoising blurs fine features like the dot in ? and arms of *)
        denoised = cv2.bilateralFilter(raw_gray, d=5, sigmaColor=40, sigmaSpace=40)

        # Otsu threshold works better than adaptive for uniform dark backgrounds
        _, otsu_bin = cv2.threshold(denoised, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        # Invert: dark text on white for OCR
        ocr_bin_inv = cv2.bitwise_not(otsu_bin)
        # Clean noise only when speckle is actually present.
        speckle = estimate_binary_speckle_ratio(otsu_bin)
        if speckle >= 0.09:
            kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (2, 2))
            ocr_bin_inv = cv2.morphologyEx(ocr_bin_inv, cv2.MORPH_OPEN, kernel, iterations=1)
        elif speckle >= 0.03:
            ocr_bin_inv = cv2.medianBlur(ocr_bin_inv, 3)

        enh_gray = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8)).apply(denoised)

        # Inverted grayscale: dark text on bright bg (preserves all gray-level detail)
        # EasyOCR may prefer this standard polarity for recognition
        inv_gray = cv2.bitwise_not(denoised)
        sharp_gray = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8)).apply(inv_gray)

        # Illumination-invariant via L channel
        lab = cv2.cvtColor(crop, cv2.COLOR_BGR2LAB)
        l_ch = lab[:, :, 0]
        l_norm = cv2.normalize(l_ch, None, 0, 255, cv2.NORM_MINMAX)
        norm_gray = cv2.createCLAHE(clipLimit=2.5, tileGridSize=(8, 8)).apply(l_norm)

        return denoised, enh_gray, ocr_bin_inv, norm_gray, sharp_gray
    else:
        # Original path for normal lighting conditions
        raw_gray = cv2.fastNlMeansDenoising(raw_gray, None, h=6, templateWindowSize=7, searchWindowSize=21)
        enh_gray = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8)).apply(raw_gray)
        bin_img = cv2.adaptiveThreshold(
            enh_gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, blockSize=31, C=-2
        )
        ocr_bin_inv = cv2.bitwise_not(bin_img)

        lab = cv2.cvtColor(crop, cv2.COLOR_BGR2LAB)
        l_ch = lab[:, :, 0]
        l_norm = cv2.normalize(l_ch, None, 0, 255, cv2.NORM_MINMAX)
        norm_gray = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8)).apply(l_norm)

        return raw_gray, enh_gray, ocr_bin_inv, norm_gray, None


def image_quality_score(gray_img):
    lap = cv2.Laplacian(gray_img, cv2.CV_64F)
    edge_score = float(np.std(lap))
    contrast = float(np.std(gray_img))
    return edge_score * contrast


def read_text(reader, image):
    return reader.readtext(
        image,
        decoder="beamsearch",
        beamWidth=EASYOCR_BEAM_WIDTH,
        paragraph=False,
        text_threshold=0.7,
        low_text=0.3,
        width_ths=0.8,
        min_size=8,
        allowlist=ALLOWLIST,
    )


def read_text_bright(reader, image):
    """Relaxed parameters for bright-on-dark phone screenshots."""
    return reader.readtext(
        image,
        decoder="beamsearch",
        beamWidth=EASYOCR_BEAM_WIDTH,
        paragraph=False,
        text_threshold=0.5,
        low_text=0.2,
        width_ths=1.5,
        add_margin=0.15,
        min_size=6,
        allowlist=ALLOWLIST,
    )


def has_strong_result(results):
    for (_, text, conf) in results:
        if conf >= 0.50 and len(text.strip()) >= 2:
            return True
    return False


def score_result(results, combined):
    if not combined:
        return 0.0
    avg_conf = sum(conf for (_, _, conf) in results) / max(1, len(results))
    symbol_count = sum(1 for ch in combined if not ch.isalnum())
    symbol_bonus = min(2.6, symbol_count * 0.45)
    if len(combined) > 18:
        symbol_bonus -= (len(combined) - 18) * 2.1
    penalty = 0.0

    # OCR artifact penalty: symbol-digit-symbol insertions are common false joins.
    for i in range(1, len(combined) - 1):
        if (not combined[i - 1].isalnum()) and combined[i].isdigit() and (not combined[i + 1].isalnum()):
            penalty += 1.6

    # OCR artifact penalty: long trailing digit runs often come from UI noise.
    tail_digits = 0
    for ch in reversed(combined):
        if ch.isdigit():
            tail_digits += 1
        else:
            break
    if tail_digits >= 2:
        penalty += (tail_digits - 1) * 1.35

    return len(combined) * 1.6 + avg_conf * 4.0 + symbol_bonus - penalty


def candidate_confidence(results):
    weighted = 0.0
    total_w = 0.0
    for (_, text, conf) in results:
        t = text.strip()
        if not t:
            continue
        w = float(max(1, len(t)))
        weighted += float(conf) * w
        total_w += w
    if total_w <= 0.0:
        return 0.0
    return weighted / total_w


def combine_tokens(results):
    tokens = []
    for (bbox, text, conf) in results:
        t = text.strip()
        if not t or conf < 0.2:
            continue
        x0 = min(p[0] for p in bbox)
        y0 = min(p[1] for p in bbox)
        x1 = max(p[0] for p in bbox)
        y1 = max(p[1] for p in bbox)
        cy = (y0 + y1) * 0.5
        h = max(1.0, y1 - y0)
        tokens.append((cy, x0, t, conf, h))
    if not tokens:
        return ""

    # Cluster tokens into text rows, then keep the most complete row.
    tokens.sort(key=lambda t: t[0])
    row_tol = max(16.0, np.median([t[4] for t in tokens]) * 0.85)
    rows = []
    for tok in tokens:
        if not rows:
            rows.append([tok])
            continue
        if abs(tok[0] - rows[-1][-1][0]) <= row_tol:
            rows[-1].append(tok)
        else:
            rows.append([tok])

    best_row = max(rows, key=lambda row: (sum(len(t[2]) for t in row), sum(t[3] for t in row)))
    best_row.sort(key=lambda t: t[1])
    return "".join(t[2] for t in best_row)


def sanitize_text(text):
    if not text:
        return ""
    allowed = set(ALLOWLIST)
    return "".join(ch for ch in text if ch in allowed)


def bounded_levenshtein(a, b, max_dist):
    la = len(a)
    lb = len(b)
    if abs(la - lb) > max_dist:
        return max_dist + 1
    prev = list(range(lb + 1))
    cur = [0] * (lb + 1)
    for i in range(1, la + 1):
        cur[0] = i
        row_min = cur[0]
        ca = a[i - 1]
        for j in range(1, lb + 1):
            cost = 0 if ca == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if cur[j] < row_min:
                row_min = cur[j]
        if row_min > max_dist:
            return max_dist + 1
        prev, cur = cur, prev
    return prev[lb]


def align_to_reference(reference, text):
    m = len(reference)
    n = len(text)
    if m == 0:
        return []
    if n == 0:
        return [None] * m

    dp = [[0] * (n + 1) for _ in range(m + 1)]
    back = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        dp[i][0] = i
        back[i][0] = 1  # delete from reference
    for j in range(1, n + 1):
        dp[0][j] = j
        back[0][j] = 2  # insert in reference (skip char in text)

    for i in range(1, m + 1):
        rch = reference[i - 1]
        for j in range(1, n + 1):
            tch = text[j - 1]
            sub_cost = 0 if rch == tch else 1
            sub = dp[i - 1][j - 1] + sub_cost
            delete = dp[i - 1][j] + 1
            insert = dp[i][j - 1] + 1
            best = sub
            op = 0
            if delete < best:
                best = delete
                op = 1
            if insert < best:
                best = insert
                op = 2
            dp[i][j] = best
            back[i][j] = op

    aligned = [None] * m
    i = m
    j = n
    while i > 0 or j > 0:
        if i == 0:
            j -= 1
            continue
        if j == 0:
            i -= 1
            continue
        op = back[i][j]
        if op == 0:
            aligned[i - 1] = text[j - 1]
            i -= 1
            j -= 1
        elif op == 1:
            i -= 1
        else:
            j -= 1
    return aligned


def position_vote(variants):
    if not variants:
        return ""
    if len(variants) == 1:
        return variants[0][0]

    len_weight = {}
    for text, weight in variants:
        l = len(text)
        len_weight[l] = len_weight.get(l, 0.0) + max(0.01, float(weight))
    target_len = max(len_weight.items(), key=lambda kv: kv[1])[0]
    reference = max(
        variants,
        key=lambda v: (-abs(len(v[0]) - target_len), max(0.01, float(v[1]))),
    )[0]
    if not reference:
        reference = variants[0][0]
    out = []
    for i in range(len(reference)):
        votes = {}
        for t, w in variants:
            if not t:
                continue
            weight = max(0.01, float(w)) / (1.0 + abs(len(t) - target_len) * 0.35)
            aligned = align_to_reference(reference, t)
            if i >= len(aligned):
                continue
            ch = aligned[i]
            if ch is None:
                continue
            votes[ch] = votes.get(ch, 0.0) + weight
        if votes:
            out.append(max(votes.items(), key=lambda kv: kv[1])[0])
        else:
            out.append(reference[i])
    return "".join(out)


def pattern_score(text):
    if not text:
        return -999.0
    l = len(text)
    upp = sum(1 for ch in text if "A" <= ch <= "Z")
    low = sum(1 for ch in text if "a" <= ch <= "z")
    dig = sum(1 for ch in text if ch.isdigit())
    sym = sum(1 for ch in text if not ch.isalnum())

    score = 0.0
    if upp + low >= 3:
        score += 1.6
    if dig >= 2:
        score += 1.2
    if sym >= 2:
        score += 1.5
    if "@" in text:
        score += 0.8
    if "_" in text:
        score += 0.7
    if "@" in text and "_" in text and text.index("@") < text.rindex("_"):
        score += 2.1
    if "?" in text:
        score += 0.5
    if 12 <= l <= 18:
        score += 2.8
    elif l > 18:
        score -= (l - 18) * 1.9
    elif l < 8:
        score -= (8 - l) * 1.5
    return score


def best_text_window(text):
    text = sanitize_text(text)
    if not text:
        return ""
    def length_prior(l):
        # Gentle preference for 14-18 char windows.
        if 14 <= l <= 18:
            return 1.8
        elif l > 18:
            return 1.8 - (l - 18) * 1.2
        else:
            return 1.8 - (14 - l) * 0.5

    n = len(text)
    best = text
    best_score = pattern_score(text) + n * 0.22 + length_prior(n)
    if n >= 2 and text[-1].isdigit() and not text[-2].isdigit():
        best_score -= 0.3

    min_len = 12 if n >= 12 else n
    max_len = min(18, n)
    for win_len in range(min_len, max_len + 1):
        for i in range(0, n - win_len + 1):
            sub = text[i:i + win_len]
            score = pattern_score(sub) + win_len * 0.22 + length_prior(win_len)
            # Slight penalty for trailing isolated digit (often OCR noise
            # from phone UI icons rather than actual password characters).
            if len(sub) >= 2 and sub[-1].isdigit() and not sub[-2].isdigit():
                score -= 0.3
            if score > best_score + 1e-6:
                best_score = score
                best = sub
    return best


def normalize_ocr_text(text):
    text = sanitize_text(text)
    if not text:
        return text
    while "__" in text:
        text = text.replace("__", "_")
    return text


def normalize_ocr_ambiguities(text):
    # Backward-compatible alias used by test_ocr.py/integration callers.
    return normalize_ocr_text(text)


def select_consensus_candidate(candidates):
    entries = []
    for results, combined in candidates:
        text = normalize_ocr_text(best_text_window(combined))
        if not text:
            continue
        conf = candidate_confidence(results)
        base = score_result(results, text)
        entries.append((text, conf, base))
    if not entries:
        return "", 0.0

    # Choose a target length from weighted mode to suppress accidental long tails.
    len_weights = {}
    for text, conf, base in entries:
        l = len(text)
        len_weights[l] = len_weights.get(l, 0.0) + max(0.2, conf * 2.0) + max(0.0, base * 0.05)
    target_len = max(len_weights.items(), key=lambda kv: kv[1])[0]

    # Cluster near-duplicate readings (small OCR edits) and vote by position.
    clusters = []
    for text, conf, base in sorted(entries, key=lambda e: e[2], reverse=True):
        max_dist = 2 if len(text) <= 18 else 3
        placed = False
        for cluster in clusters:
            seed = cluster["seed"]
            if abs(len(seed) - len(text)) > max_dist:
                continue
            dist = bounded_levenshtein(seed, text, max_dist)
            if dist <= max_dist:
                cluster["variants"].append((text, conf, base))
                if base > cluster["best_base"]:
                    cluster["best_base"] = base
                    cluster["seed"] = text
                placed = True
                break
        if not placed:
            clusters.append({
                "seed": text,
                "best_base": base,
                "variants": [(text, conf, base)],
            })

    best_text = ""
    best_conf = 0.0
    best_score = -1e9
    for cluster in clusters:
        variants = cluster["variants"]
        voted = position_vote([(t, max(0.05, c) * max(1.0, len(t))) for (t, c, _) in variants])
        voted = normalize_ocr_text(best_text_window(voted))
        if not voted:
            continue
        sum_base = sum(v[2] for v in variants)
        avg_base = sum_base / max(1, len(variants))
        max_conf = max(v[1] for v in variants)
        hits = len(variants)
        len_bonus = max(0.0, 4.6 - abs(len(voted) - target_len) * 1.45)
        score = (
            avg_base * 0.95
            + pattern_score(voted) * 1.35
            + max_conf * 2.4
            + min(3, hits) * 1.1
            + len_bonus * 0.35
        )
        if score > best_score:
            best_score = score
            best_text = voted
            best_conf = max_conf

    if not best_text:
        text, conf, _ = max(entries, key=lambda e: e[2])
        return text, conf
    return best_text, best_conf


def expand_roi(roi, shape, scale_x=1.7, scale_y=1.9):
    x0, y0, x1, y1 = roi
    h, w = shape[:2]
    cx = (x0 + x1) * 0.5
    cy = (y0 + y1) * 0.5
    rw = (x1 - x0) * scale_x
    rh = (y1 - y0) * scale_y
    nx0 = max(0, int(cx - rw * 0.5))
    ny0 = max(0, int(cy - rh * 0.5))
    nx1 = min(w, int(cx + rw * 0.5))
    ny1 = min(h, int(cy + rh * 0.5))
    return (nx0, ny0, nx1, ny1)


def roi_iou(a, b):
    ax0, ay0, ax1, ay1 = a
    bx0, by0, bx1, by1 = b
    ix0 = max(ax0, bx0)
    iy0 = max(ay0, by0)
    ix1 = min(ax1, bx1)
    iy1 = min(ay1, by1)
    inter = max(0, ix1 - ix0) * max(0, iy1 - iy0)
    if inter <= 0:
        return 0.0
    aa = max(1, (ax1 - ax0) * (ay1 - ay0))
    ab = max(1, (bx1 - bx0) * (by1 - by0))
    return inter / float(max(1, aa + ab - inter))


def dedupe_rois(rois, iou_threshold=0.65, max_rois=6):
    kept = []
    for roi in rois:
        x0, y0, x1, y1 = roi
        if x1 - x0 < 8 or y1 - y0 < 8:
            continue
        if any(roi_iou(roi, k) >= iou_threshold for k in kept):
            continue
        kept.append(roi)
        if len(kept) >= max_rois:
            break
    return kept


def roi_priority_score(roi, img_shape):
    x0, y0, x1, y1 = roi
    h, w = img_shape[:2]
    rw = max(1, x1 - x0)
    rh = max(1, y1 - y0)
    area_ratio = (rw * rh) / float(max(1, w * h))
    width_ratio = rw / float(max(1, w))
    height_ratio = rh / float(max(1, h))
    aspect = rw / float(rh)

    cx = (x0 + x1) * 0.5
    cy = (y0 + y1) * 0.5
    dx = abs(cx - w * 0.5) / max(1.0, w * 0.5)
    dy = abs(cy - h * 0.62) / max(1.0, h * 0.62)
    center_bonus = max(0.0, 1.0 - 0.95 * dx - 0.70 * dy)

    score = 0.0
    # Prefer large horizontal text bands over tiny reflection snippets.
    score += width_ratio * 11.0
    score += min(4.5, area_ratio * 95.0)
    score += min(2.0, max(0.0, aspect - 1.2) * 0.18)
    score += center_bonus * 2.0

    # Strongly demote very narrow/small candidates unless nothing else exists.
    if width_ratio < 0.20:
        score -= (0.20 - width_ratio) * 22.0
    if area_ratio < 0.012:
        score -= (0.012 - area_ratio) * 120.0
    if height_ratio < 0.025:
        score -= 0.9

    return score


def prioritize_rois(rois, img_shape):
    if not rois:
        return []
    ordered = sorted(rois, key=lambda r: roi_priority_score(r, img_shape), reverse=True)
    # Ensure at least one widest candidate remains near the front for FAST_MODE paths.
    widest = max(ordered, key=lambda r: (r[2] - r[0]))
    if ordered[0] != widest:
        ordered = [ordered[0], widest] + [r for r in ordered[1:] if r != widest]
    return ordered


def propose_bright_text_rois(img, max_rois=5):
    h, w = img.shape[:2]
    if h < 40 or w < 40:
        return []

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    frame_area = float(h * w)
    cx_frame = w * 0.5
    cy_frame = h * 0.58
    candidates = []

    for perc in (85, 88, 91):
        thr = int(np.clip(np.percentile(gray, perc), 130, 245))
        bw = np.zeros_like(gray, dtype=np.uint8)
        bw[gray >= thr] = 255

        kx = max(7, int(w * 0.02))
        ky = max(3, int(h * 0.01))
        if kx % 2 == 0:
            kx += 1
        if ky % 2 == 0:
            ky += 1
        linked = cv2.morphologyEx(
            bw, cv2.MORPH_CLOSE, cv2.getStructuringElement(cv2.MORPH_RECT, (kx, ky)), iterations=1
        )
        linked = cv2.morphologyEx(
            linked, cv2.MORPH_OPEN, cv2.getStructuringElement(cv2.MORPH_RECT, (3, 3)), iterations=1
        )

        contours, _ = cv2.findContours(linked, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        for cnt in contours:
            x, y, cw, ch = cv2.boundingRect(cnt)
            area = float(cw * ch)
            if area < frame_area * 0.0008 or area > frame_area * 0.55:
                continue
            if cw < w * 0.10:
                continue
            if ch < h * 0.025 or ch > h * 0.50:
                continue
            ar = cw / float(max(1, ch))
            if ar < 1.1:
                continue

            cx = x + cw * 0.5
            cy = y + ch * 0.5
            dx = abs(cx - cx_frame) / max(1.0, w * 0.5)
            dy = abs(cy - cy_frame) / max(1.0, h * 0.65)
            center_bonus = max(0.0, 1.0 - dx - 0.8 * dy)
            width_ratio = cw / float(max(1, w))
            area_ratio = area / max(1.0, frame_area)
            score = area * (1.0 + center_bonus)
            score += width_ratio * 2200.0 + area_ratio * 1800.0

            pad_x = int(max(cw * 0.18, w * 0.01))
            pad_y = int(max(ch * 0.40, h * 0.01))
            x0 = max(0, x - pad_x)
            y0 = max(0, y - pad_y)
            x1 = min(w, x + cw + pad_x)
            y1 = min(h, y + ch + pad_y)
            candidates.append((score, (x0, y0, x1, y1)))

    candidates.sort(reverse=True, key=lambda t: t[0])
    rois = [r for (_, r) in candidates]
    return dedupe_rois(rois, iou_threshold=0.62, max_rois=max_rois)


def rotate_crop(crop, angle_deg):
    h, w = crop.shape[:2]
    if h < 4 or w < 4:
        return crop
    m = cv2.getRotationMatrix2D((w * 0.5, h * 0.5), angle_deg, 1.0)
    return cv2.warpAffine(
        crop, m, (w, h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE
    )


def run_ocr_on_crop(reader, crop_bgr, allow_bin_fallback=True, max_passes=3):
    raw_gray, enh_gray, ocr_bin, norm_gray, sharp_gray = build_ocr_inputs(crop_bgr)
    bright = sharp_gray is not None
    candidates = []
    candidate_tags = []

    def add_candidate(results, tag):
        candidates.append((results, combine_tokens(results)))
        candidate_tags.append(tag)

    if bright:
        h, w = crop_bgr.shape[:2]
        primary_scale = 2.0 if min(h, w) >= 140 else 3.0
        if abs(primary_scale - 3.0) < 1e-6:
            local_raw, local_enh, local_bin, _, local_inv = raw_gray, enh_gray, ocr_bin, norm_gray, sharp_gray
        else:
            local_raw, local_enh, local_bin, _, local_inv = build_ocr_inputs(crop_bgr, scale_override=primary_scale)

        add_candidate(read_text(reader, local_raw), "raw")
        add_candidate(read_text(reader, local_enh), "enh")
        if max_passes >= 2 and local_inv is not None:
            add_candidate(read_text(reader, local_inv), "inv")
        if max_passes >= 3 and allow_bin_fallback:
            # Recommended pipeline: crop -> upscale -> Otsu -> invert.
            add_candidate(read_text(reader, local_bin), "REC")

        cur_best = max(candidates, key=lambda c: score_result(c[0], c[1]))
        cur_best_conf = candidate_confidence(cur_best[0])
        if (not is_good_candidate(cur_best[0], cur_best[1])) or len(cur_best[1]) < 15 or cur_best_conf < 0.88:
            add_candidate(read_text_bright(reader, local_enh), "bright_relaxed")

            alt_scale = 3.0 if abs(primary_scale - 2.0) < 1e-6 else 2.0
            alt_raw, alt_enh, _, _, alt_inv = build_ocr_inputs(crop_bgr, scale_override=alt_scale)
            add_candidate(read_text(reader, alt_raw), f"raw_s{alt_scale:.1f}")
            add_candidate(read_text(reader, alt_enh), f"enh_s{alt_scale:.1f}")
            if alt_inv is not None:
                add_candidate(read_text(reader, alt_inv), f"inv_s{alt_scale:.1f}")

        vote_inputs = []
        for r, t in candidates:
            t_clean = normalize_ocr_text(t)
            if t_clean and len(t_clean) >= 8:
                vote_inputs.append((t_clean, max(0.1, candidate_confidence(r))))
        if len(vote_inputs) >= 2:
            voted = normalize_ocr_text(position_vote(vote_inputs))
            if voted:
                best_r = max(candidates, key=lambda c: score_result(c[0], c[1]))[0]
                candidates.append((best_r, voted))
                candidate_tags.append("vote")
    else:
        scored = [(raw_gray, "raw"), (enh_gray, "enh"), (norm_gray, "norm")]
        scored.sort(key=lambda pair: image_quality_score(pair[0]), reverse=True)
        first_img = scored[0][0]
        second_img = scored[1][0]
        first_tag = scored[0][1]
        second_tag = scored[1][1]

        add_candidate(read_text(reader, first_img), first_tag)
        best = max(candidates, key=lambda c: score_result(c[0], c[1]))
        if max_passes >= 2 and not is_good_candidate(best[0], best[1]):
            add_candidate(read_text(reader, second_img), second_tag)
            best = max(candidates, key=lambda c: score_result(c[0], c[1]))
        if max_passes >= 3 and allow_bin_fallback and not is_good_candidate(best[0], best[1]):
            add_candidate(read_text(reader, ocr_bin), "bin")

    if not candidates:
        return [], ""

    if DEBUG_OCR_LOG:
        for idx, ((r, t), tag) in enumerate(zip(candidates, candidate_tags)):
            t_clean = normalize_ocr_text(t)
            conf = candidate_confidence(r)
            score = score_result(r, t_clean) + (REC_PIPELINE_BONUS if tag == "REC" else 0.0)
            rec_suffix = " REC" if tag == "REC" else ""
            sys.stderr.write(
                f"  cand[{idx}] {tag}{rec_suffix}: conf={conf:.3f} score={score:.2f}\n"
            )

    norm_candidates = []
    for (r, t), tag in zip(candidates, candidate_tags):
        t_clean = normalize_ocr_text(t)
        bonus = REC_PIPELINE_BONUS if tag == "REC" else 0.0
        norm_candidates.append((r, t_clean, bonus, tag))
    valid_entries = []
    for (r, t, bonus, tag) in norm_candidates:
        if not t:
            continue
        valid_entries.append({
            "results": r,
            "text": t,
            "base": score_result(r, t) + bonus,
            "conf": candidate_confidence(r),
            # "vote" is a synthetic aggregate of the same pass list; reduce its support weight
            # so it does not dominate repeated-evidence scoring on its own.
            "weight": 0.45 if tag == "vote" else 1.0,
        })

    if not valid_entries:
        results, combined, _, _ = max(norm_candidates, key=lambda c: score_result(c[0], c[1]) + c[2])
        return results, combined

    # Reliability-first selection: repeated near-matching readings beat single-pass outliers.
    clusters = []
    for entry in sorted(valid_entries, key=lambda e: e["base"], reverse=True):
        placed = False
        for cluster in clusters:
            seed = cluster["seed"]
            max_dist = 2 if max(len(seed), len(entry["text"])) <= 18 else 3
            if abs(len(seed) - len(entry["text"])) > max_dist:
                continue
            dist = bounded_levenshtein(seed, entry["text"], max_dist)
            if dist <= max_dist:
                cluster["items"].append(entry)
                if entry["base"] > cluster["best_base"]:
                    cluster["best_base"] = entry["base"]
                    cluster["seed"] = entry["text"]
                placed = True
                break
        if not placed:
            clusters.append({
                "seed": entry["text"],
                "best_base": entry["base"],
                "items": [entry],
            })

    best_cluster = None
    best_rank = -1e9
    for cluster in clusters:
        items = cluster["items"]
        support = sum(item["weight"] for item in items)
        vote_inputs = [(item["text"], max(0.05, item["conf"]) * max(1.0, float(len(item["text"])))) for item in items]
        voted = normalize_ocr_text(best_text_window(position_vote(vote_inputs)))
        if not voted:
            voted = cluster["seed"]
        peak_base = max(item["base"] for item in items)
        avg_conf = sum(item["conf"] * item["weight"] for item in items) / max(0.01, support)
        rank = peak_base + min(5.0, max(0.0, support - 1.0) * 1.8) + avg_conf * 1.1 + pattern_score(voted) * 0.12
        if rank > best_rank:
            best_rank = rank
            best_cluster = (cluster, voted)

    cluster, combined = best_cluster
    chosen = None
    chosen_rank = -1e9
    for item in cluster["items"]:
        max_dist = 2 if max(len(combined), len(item["text"])) <= 18 else 3
        dist = bounded_levenshtein(combined, item["text"], max_dist)
        if dist > max_dist:
            dist = max_dist + 1
        item_rank = item["base"] * 0.06 + item["conf"] * 1.8 - dist * 1.1
        if item_rank > chosen_rank:
            chosen_rank = item_rank
            chosen = item
    results = chosen["results"]

    # Keep consensus as a tie-breaker when it agrees with or improves the chosen cluster.
    consensus_text, _ = select_consensus_candidate([(r, t) for (r, t, _, _) in norm_candidates])
    if consensus_text:
        max_dist = 2 if max(len(combined), len(consensus_text)) <= 18 else 3
        if abs(len(combined) - len(consensus_text)) <= max_dist:
            dist = bounded_levenshtein(combined, consensus_text, max_dist)
            if dist <= max_dist:
                combined = consensus_text
    return results, combined


def main():
    global DEBUG_PREPASS, DEBUG_OCR_LOG, FAST_MODE, MAX_INPUT_SIDE, EASYOCR_BEAM_WIDTH, REC_PIPELINE_BONUS, ALLOWLIST
    DEBUG_PREPASS = env_flag_enabled("TESS_OCR_DEBUG_PREPASS")
    DEBUG_OCR_LOG = env_flag_enabled("TESS_OCR_DEBUG")
    FAST_MODE = env_flag_default_on("TESS_OCR_FAST_MODE")
    MAX_INPUT_SIDE = env_int_or_default("TESS_OCR_MAX_SIDE", 1120 if FAST_MODE else 1280, 480, 1920)
    custom_allowlist = os.environ.get("TESS_OCR_ALLOWLIST")
    if custom_allowlist:
        ALLOWLIST = custom_allowlist
    EASYOCR_BEAM_WIDTH = env_int_or_default("TESS_OCR_BEAM_WIDTH", 10, 1, 30)
    REC_PIPELINE_BONUS = env_int_or_default("TESS_OCR_REC_BONUS_X100", 45, 0, 300) / 100.0
    min_roi_contrast = env_int_or_default("TESS_OCR_MIN_ROI_CONTRAST", 25, 0, 255)

    torch_threads = env_int_or_default("TESS_OCR_TORCH_THREADS", 1, 1, 16)
    cv_threads = env_int_or_default("TESS_OCR_CV_THREADS", 1, 1, 8)
    try:
        torch.set_num_threads(torch_threads)
        # Keep inter-op low to avoid contention when many workers are active.
        torch.set_num_interop_threads(1)
    except Exception:
        pass
    try:
        cv2.setNumThreads(cv_threads)
    except Exception:
        pass

    use_gpu, gpu_mode = choose_gpu_mode()
    allow_model_download = env_flag_enabled("TESS_OCR_ALLOW_MODEL_DOWNLOAD")
    model_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
    reader = None

    def ensure_reader():
        nonlocal reader, use_gpu
        if reader is not None:
            return reader
        try:
            reader = easyocr.Reader(
                ["en"], gpu=use_gpu, verbose=False,
                model_storage_directory=model_dir,
                download_enabled=allow_model_download,
            )
        except Exception as ex:
            if use_gpu:
                sys.stderr.write(f"OCR GPU init failed ({ex}), falling back to CPU\n")
                use_gpu = False
                reader = easyocr.Reader(
                    ["en"], gpu=False, verbose=False,
                    model_storage_directory=model_dir,
                    download_enabled=allow_model_download,
                )
            else:
                raise
        sys.stderr.write(
            f"OCR backend: {'GPU' if use_gpu else 'CPU'} (mode={gpu_mode}) "
            f"fast={1 if FAST_MODE else 0} maxSide={MAX_INPUT_SIDE} "
            f"beam={EASYOCR_BEAM_WIDTH} "
            f"recBonus={REC_PIPELINE_BONUS:.2f} "
            f"torchThreads={torch_threads} cvThreads={cv_threads}\n"
        )
        return reader

    # Protocol: read 4-byte little-endian size, then that many PNG bytes. Repeat.
    # Write back: UTF-8 text lines, then a lone newline to signal end of result.
    while True:
        header = sys.stdin.buffer.read(4)
        if len(header) < 4:
            break

        size = struct.unpack("<I", header)[0]
        data = sys.stdin.buffer.read(size)
        if len(data) < size:
            break

        img = cv2.imdecode(np.frombuffer(data, dtype=np.uint8), cv2.IMREAD_COLOR)
        if img is None:
            sys.stdout.buffer.write(b"\n")
            sys.stdout.buffer.flush()
            continue

        # Keep frames bounded for latency.
        img = downscale_for_speed(img)
        base_img = img.copy()

        # Enhance local contrast so the dot in ! is more distinct from I
        lab = cv2.cvtColor(img, cv2.COLOR_BGR2LAB)
        l, a, b = cv2.split(lab)
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        l = clahe.apply(l)
        img = cv2.cvtColor(cv2.merge([l, a, b]), cv2.COLOR_LAB2BGR)

        # Sharpen to help with webcam blur
        blur = cv2.GaussianBlur(img, (0, 0), 3)
        img = cv2.addWeighted(img, 1.5, blur, -0.5, 0)

        screen_roi = detect_phone_screen_roi(base_img, warp_source=img)
        if screen_roi is not None and screen_roi.get("warped") is not None:
            work_img = screen_roi["warped"]
        else:
            work_img = img

        gray = cv2.cvtColor(work_img, cv2.COLOR_BGR2GRAY)
        mask = build_text_mask(gray)
        roi = find_text_roi(mask)
        roi_candidates = []
        roi_clipped = False
        if roi is not None:
            x0, y0, x1, y1, roi_clipped = roi
            roi_candidates.append((x0, y0, x1, y1))
            if roi_clipped:
                # When ROI is clipped at frame edge, add a full-width version
                # with same vertical bounds to catch characters beyond the clip.
                wh, ww = work_img.shape[:2]
                roi_candidates.append((0, max(0, y0), ww, min(wh, y1)))
        roi_candidates.extend(propose_bright_text_rois(work_img, max_rois=5 if FAST_MODE else 7))
        roi_candidates = dedupe_rois(roi_candidates, iou_threshold=0.62, max_rois=6 if FAST_MODE else 9)
        roi_candidates = prioritize_rois(roi_candidates, work_img.shape)
        if not roi_candidates:
            roi_candidates = [(0, 0, work_img.shape[1], work_img.shape[0])]
        x0, y0, x1, y1 = roi_candidates[0]
        roi_bgr = work_img[y0:y1, x0:x1]

        # Keep a quick metric for optional debug overlays.
        roi_gray_check = cv2.cvtColor(roi_bgr, cv2.COLOR_BGR2GRAY)
        roi_contrast = float(np.std(roi_gray_check))

        if DEBUG_PREPASS:
            vis = work_img.copy()
            cv2.rectangle(vis, (x0, y0), (x1, y1), (0, 255, 0), 2)
            label = f"c={roi_contrast:.0f}"
            if roi_clipped:
                label += " CLIP"
            cv2.putText(vis, label, (x0, max(y0 - 6, 12)),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 1)
            cv2.imshow("ROI", cv2.resize(vis, None, fx=0.6, fy=0.6))
            # Show the preprocessed image that OCR will actually read.
            raw_g, enh_g, _, norm_g, sharp_g = build_ocr_inputs(roi_bgr)
            scored_dbg = [(raw_g, "raw"), (enh_g, "enh"), (norm_g, "norm")]
            if sharp_g is not None:
                scored_dbg.append((sharp_g, "sharp"))
            scored_dbg.sort(key=lambda p: image_quality_score(p[0]), reverse=True)
            ocr_preview = scored_dbg[0][0]
            ocr_vis = cv2.cvtColor(ocr_preview, cv2.COLOR_GRAY2BGR)
            cv2.putText(ocr_vis, scored_dbg[0][1], (4, 20),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 1)
            cv2.imshow("OCR Input", ocr_vis)
            cv2.waitKey(1)

        candidates = []
        reader = ensure_reader()

        fast_passes = 2 if FAST_MODE else 3

        # Pass 1: try multiple adaptive ROIs.
        max_rois = 3 if FAST_MODE else len(roi_candidates)
        cand_results, cand_text = ([], "")
        roi_attempts = []
        for idx, (rx0, ry0, rx1, ry1) in enumerate(roi_candidates[:max_rois]):
            crop = work_img[ry0:ry1, rx0:rx1]
            local_gray = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY)
            local_contrast = float(np.std(local_gray))
            allow_fallback = (not FAST_MODE) or (idx == 0 and local_contrast >= min_roi_contrast)
            rr, rt = run_ocr_on_crop(
                reader, crop, allow_bin_fallback=allow_fallback, max_passes=fast_passes
            )
            candidates.append((rr, rt))
            roi_attempts.append((rx0, ry0, rx1, ry1, rr, rt))
            if idx == 0:
                cand_results, cand_text = rr, rt
            if is_good_candidate(rr, rt) and candidate_confidence(rr) >= 0.86 and len(rt) >= 16:
                break

        if not candidates:
            rr, rt = run_ocr_on_crop(reader, work_img, allow_bin_fallback=True, max_passes=fast_passes)
            candidates.append((rr, rt))
            cand_results, cand_text = rr, rt

        # Fast-mode recovery: if quick passes are weak, retry same ROI with full passes.
        cur_best = max(candidates, key=lambda c: score_result(c[0], c[1]))
        if FAST_MODE and not is_good_candidate(cur_best[0], cur_best[1]):
            for rx0, ry0, rx1, ry1 in roi_candidates[:1]:
                rec_crop = work_img[ry0:ry1, rx0:rx1]
                rec_results, rec_text = run_ocr_on_crop(
                    reader, rec_crop, allow_bin_fallback=True, max_passes=3
                )
                candidates.append((rec_results, rec_text))

        # Pass 2: mirrored ROI only if first pass is weak.
        if (not FAST_MODE) and (not is_good_candidate(cand_results, cand_text)):
            mirror_results, mirror_text = run_ocr_on_crop(
                reader, cv2.flip(roi_bgr, 1), allow_bin_fallback=True, max_passes=3
            )
            candidates.append((mirror_results, mirror_text))

        # Pass 3/4: expanded ROI only when still weak.
        cur_best = max(candidates, key=lambda c: score_result(c[0], c[1]))
        if not is_good_candidate(cur_best[0], cur_best[1]):
            for rx0, ry0, rx1, ry1 in roi_candidates[:1]:
                ex0, ey0, ex1, ey1 = expand_roi((rx0, ry0, rx1, ry1), work_img.shape)
                if (ex0, ey0, ex1, ey1) == (rx0, ry0, rx1, ry1):
                    continue
                expanded = work_img[ey0:ey1, ex0:ex1]
                exp_passes = 2 if FAST_MODE else 3
                exp_results, exp_text = run_ocr_on_crop(
                    reader, expanded, allow_bin_fallback=True, max_passes=exp_passes
                )
                candidates.append((exp_results, exp_text))
                if (not FAST_MODE) and (not is_good_candidate(exp_results, exp_text)):
                    exp_m_results, exp_m_text = run_ocr_on_crop(
                        reader, cv2.flip(expanded, 1), allow_bin_fallback=True, max_passes=3
                    )
                    candidates.append((exp_m_results, exp_m_text))

        # Rotation recovery for tilted captures. Trigger when best candidate is
        # still uncertain or appears truncated.
        cur_best = max(candidates, key=lambda c: score_result(c[0], c[1]))
        best_conf_now = candidate_confidence(cur_best[0])
        if (best_conf_now < 0.80) or (len(cur_best[1]) < 16):
            seed_rois = []
            for rx0, ry0, rx1, ry1, rr, rt in sorted(
                roi_attempts, key=lambda t: score_result(t[4], t[5]), reverse=True
            ):
                if (rx0, ry0, rx1, ry1) in seed_rois:
                    continue
                if rt:
                    seed_rois.append((rx0, ry0, rx1, ry1))
                if len(seed_rois) >= 2:
                    break
            if not seed_rois:
                seed_rois = roi_candidates[:1]

            for rx0, ry0, rx1, ry1 in seed_rois:
                crop = work_img[ry0:ry1, rx0:rx1]
                for ang in (-8, -5, 5, 8):
                    rotated = rotate_crop(crop, ang)
                    rot_results, rot_text = run_ocr_on_crop(
                        reader, rotated, allow_bin_fallback=False, max_passes=2
                    )
                    candidates.append((rot_results, rot_text))

        # If perspective-warp path is weak, also try non-warp crops as a safety net.
        cur_best = max(candidates, key=lambda c: score_result(c[0], c[1]))
        if (not is_good_candidate(cur_best[0], cur_best[1])) or (len(cur_best[1]) < 16):
            fallback_views = []
            if screen_roi is not None:
                bx0, by0, bx1, by1 = screen_roi["bbox"]
                if (bx1 - bx0) >= 16 and (by1 - by0) >= 16:
                    fallback_views.append(("bbox", img[by0:by1, bx0:bx1]))
            fallback_views.append(("full", img))

            for name, view in fallback_views:
                if view is None or view.size == 0:
                    continue
                v_gray = cv2.cvtColor(view, cv2.COLOR_BGR2GRAY)
                v_mask = build_text_mask(v_gray)
                v_roi = find_text_roi(v_mask)
                if v_roi is not None:
                    vx0, vy0, vx1, vy1, _ = v_roi
                    view_crop = view[vy0:vy1, vx0:vx1]
                else:
                    view_crop = view
                fb_results, fb_text = run_ocr_on_crop(
                    reader, view_crop, allow_bin_fallback=True, max_passes=3
                )
                if DEBUG_OCR_LOG:
                    sys.stderr.write(
                        f"  fallback[{name}] conf={candidate_confidence(fb_results):.3f}\n"
                    )
                candidates.append((fb_results, fb_text))

        # Pick the strongest cluster consensus across all candidate passes.
        results, combined = max(candidates, key=lambda c: score_result(c[0], c[1]))
        consensus_text, consensus_conf = select_consensus_candidate(candidates)
        if consensus_text:
            combined = consensus_text

        if combined:
            combined = normalize_ocr_text(best_text_window(combined))

        if DEBUG_OCR_LOG:
            for (bbox, text, conf) in results:
                sys.stderr.write(f"  ocr: conf={conf:.2f}\n")
        if combined:
            conf = consensus_conf if consensus_text else candidate_confidence(results)
            if roi_clipped:
                conf *= 0.70
            # Protocol line: FINAL<TAB>{conf}<TAB>{text}
            sys.stdout.buffer.write((f"FINAL\t{conf:.4f}\t{combined}\n").encode("utf-8"))
        if not results and DEBUG_OCR_LOG:
            sys.stderr.write("  ocr: (no text detected)\n")

        # Empty line signals end of this frame's results
        sys.stdout.buffer.write(b"\n")
        sys.stdout.buffer.flush()

if __name__ == "__main__":
    main()
