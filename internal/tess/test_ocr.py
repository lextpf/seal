"""Test OCR preprocessing on example images."""
import sys
import os
import glob

# Ensure we can import from this directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
CPU_COUNT = max(1, int(os.cpu_count() or 1))
DEFAULT_TORCH_THREADS = max(1, min(8, CPU_COUNT))
DEFAULT_CV_THREADS = max(1, min(4, DEFAULT_TORCH_THREADS))

os.environ.setdefault("TESS_OCR_DEBUG_PREPASS", "0")
os.environ.setdefault("TESS_OCR_DEBUG", "0")
# Prefer GPU automatically when CUDA is available; caller can still override.
os.environ.setdefault("TESS_OCR_BACKEND", "auto")
os.environ.setdefault("TESS_OCR_TORCH_THREADS", str(DEFAULT_TORCH_THREADS))
os.environ.setdefault("TESS_OCR_CV_THREADS", str(DEFAULT_CV_THREADS))
os.environ.setdefault("OMP_NUM_THREADS", os.environ.get("TESS_OCR_TORCH_THREADS", "1"))
os.environ.setdefault("MKL_NUM_THREADS", os.environ.get("TESS_OCR_TORCH_THREADS", "1"))

import cv2
import numpy as np
import easyocr
import torch

import ocr as ocr_mod
ocr_mod.DEBUG_OCR_LOG = os.environ.get("TESS_OCR_DEBUG", "").strip().lower() in ("1", "true", "yes", "on")

TEST_VERBOSE = os.environ.get("TESS_TEST_OCR_VERBOSE", "").strip().lower() in ("1", "true", "yes", "on")


def vprint(msg):
    if TEST_VERBOSE:
        print(msg)

from ocr import (
    detect_phone_screen_roi,
    build_text_mask,
    find_text_roi,
    build_ocr_inputs,
    propose_bright_text_rois,
    dedupe_rois,
    read_text,
    combine_tokens,
    run_ocr_on_crop,
    is_good_candidate,
    score_result,
    candidate_confidence,
    select_consensus_candidate,
    normalize_ocr_ambiguities,
    best_text_window,
    downscale_for_speed,
    ALLOWLIST,
    MAX_INPUT_SIDE,
)

EXPECTED = [
    "T3*1-B?+AcJ3@_9L3n",
    "Ab?34-N*c@8_6wxK7v",
    "Hc5:f-?29+n@xPey$q",
]

def configure_runtime_limits():
    torch_threads = ocr_mod.env_int_or_default("TESS_OCR_TORCH_THREADS", 1, 1, 16)
    cv_threads = ocr_mod.env_int_or_default("TESS_OCR_CV_THREADS", 1, 1, 8)
    try:
        torch.set_num_threads(torch_threads)
        torch.set_num_interop_threads(1)
    except Exception:
        pass
    try:
        cv2.setNumThreads(cv_threads)
    except Exception:
        pass
    return torch_threads, cv_threads

def normalize_candidate_text(text):
    if not text:
        return ""
    return normalize_ocr_ambiguities(best_text_window(text))

def choose_reliable_result(candidates):
    if not candidates:
        return [], ""

    entries = []
    for results, text in candidates:
        clean = normalize_candidate_text(text)
        if not clean:
            continue
        conf = candidate_confidence(results)
        base = score_result(results, clean)
        entries.append({
            "results": results,
            "text": clean,
            "conf": conf,
            "base": base,
        })

    if not entries:
        return max(candidates, key=lambda c: score_result(c[0], c[1]))

    clusters = []
    for entry in sorted(entries, key=lambda e: e["base"], reverse=True):
        placed = False
        for cluster in clusters:
            seed = cluster["seed"]
            max_dist = 2 if max(len(seed), len(entry["text"])) <= 18 else 3
            if abs(len(seed) - len(entry["text"])) > max_dist:
                continue
            dist = ocr_mod.bounded_levenshtein(seed, entry["text"], max_dist)
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

    best_rank = -1e9
    best_payload = None
    for cluster in clusters:
        items = cluster["items"]
        hits = len(items)
        vote_inputs = [
            (item["text"], max(0.05, item["conf"]) * max(1.0, float(len(item["text"]))))
            for item in items
        ]
        voted = normalize_candidate_text(ocr_mod.position_vote(vote_inputs))
        if not voted:
            voted = cluster["seed"]
        max_base = max(item["base"] for item in items)
        support = sum(max(0.20, item["conf"]) for item in items)
        rank = (
            max_base
            + min(6.0, (hits - 1) * 2.0)
            + min(3.0, support * 0.9)
            + ocr_mod.pattern_score(voted) * 0.25
        )
        if rank > best_rank:
            best_rank = rank
            best_payload = (cluster, voted, hits, max_base)

    cluster, voted, hits, max_base = best_payload
    chosen = None
    chosen_rank = -1e9
    for item in cluster["items"]:
        max_dist = 2 if max(len(voted), len(item["text"])) <= 18 else 3
        dist = ocr_mod.bounded_levenshtein(voted, item["text"], max_dist)
        if dist > max_dist:
            dist = max_dist + 1
        item_rank = item["conf"] * 2.0 + item["base"] * 0.05 - dist * 1.2
        if item_rank > chosen_rank:
            chosen_rank = item_rank
            chosen = item

    best_single = max(entries, key=lambda e: e["base"])
    if hits <= 1 and (best_single["base"] - max_base) > 1.5:
        return best_single["results"], best_single["text"]

    return chosen["results"], voted

def main():
    examples_dir = os.path.join(os.path.dirname(__file__), "..", "..", "examples")
    examples_dir = os.path.normpath(examples_dir)

    images = sorted(glob.glob(os.path.join(examples_dir, "*.png")))
    if not images:
        print(f"No images found in {examples_dir}")
        return

    model_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
    torch_threads, cv_threads = configure_runtime_limits()
    use_gpu, gpu_mode = ocr_mod.choose_gpu_mode()
    print(
        f"Loading EasyOCR (model_dir={model_dir}) "
        f"backend={'GPU' if use_gpu else 'CPU'} (mode={gpu_mode}) "
        f"torchThreads={torch_threads} cvThreads={cv_threads}..."
    )
    try:
        reader = easyocr.Reader(
            ["en"], gpu=use_gpu, verbose=False,
            model_storage_directory=model_dir,
            download_enabled=False,
        )
    except Exception as ex:
        if use_gpu:
            print(f"GPU init failed ({ex}), falling back to CPU")
            use_gpu = False
            reader = easyocr.Reader(
                ["en"], gpu=False, verbose=False,
                model_storage_directory=model_dir,
                download_enabled=False,
            )
        else:
            raise
    print("Reader loaded.\n")

    correct = 0
    total = len(images)

    for img_path in images:
        fname = os.path.basename(img_path)
        img = cv2.imread(img_path)
        if img is None:
            print(f"[SKIP] {fname}: could not load")
            continue

        img = downscale_for_speed(img)
        base_img = img.copy()

        # Frame-level preprocessing (same as ocr.py main loop)
        lab = cv2.cvtColor(img, cv2.COLOR_BGR2LAB)
        l, a, b = cv2.split(lab)
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        l = clahe.apply(l)
        img = cv2.cvtColor(cv2.merge([l, a, b]), cv2.COLOR_LAB2BGR)
        blur_k = cv2.GaussianBlur(img, (0, 0), 3)
        img = cv2.addWeighted(img, 1.5, blur_k, -0.5, 0)

        screen_roi = detect_phone_screen_roi(base_img, warp_source=img)
        if screen_roi is not None and screen_roi.get("warped") is not None:
            sx0, sy0, sx1, sy1 = screen_roi["bbox"]
            work_img = screen_roi["warped"]
            vprint(f"  Phone screen ROI: ({sx0},{sy0})-({sx1},{sy1}) [warped]")
        else:
            work_img = img
            vprint("  No phone screen detected, using full frame")

        gray = cv2.cvtColor(work_img, cv2.COLOR_BGR2GRAY)
        mask = build_text_mask(gray)
        roi = find_text_roi(mask)

        roi_candidates = []
        if roi is not None:
            x0, y0, x1, y1, clipped = roi
            roi_candidates.append((x0, y0, x1, y1))
            vprint(f"  Text ROI: ({x0},{y0})-({x1},{y1}) clipped={clipped}")
            if clipped:
                # When ROI is clipped at frame edge, add a full-width version
                # with the same vertical bounds to catch missing characters
                wh, ww = work_img.shape[:2]
                roi_candidates.append((0, max(0, y0), ww, min(wh, y1)))

        roi_candidates.extend(propose_bright_text_rois(work_img, max_rois=5))
        roi_candidates = dedupe_rois(roi_candidates, iou_threshold=0.62, max_rois=6)

        if not roi_candidates:
            roi_candidates = [(0, 0, work_img.shape[1], work_img.shape[0])]

        candidates = []
        for idx, (rx0, ry0, rx1, ry1) in enumerate(roi_candidates[:6]):
            crop = work_img[ry0:ry1, rx0:rx1]
            rr, rt = run_ocr_on_crop(reader, crop, allow_bin_fallback=True, max_passes=4)
            candidates.append((rr, rt))
            conf = candidate_confidence(rr)
            vprint(f"  ROI[{idx}] conf={conf:.3f} score={score_result(rr, rt):.1f}")
            if is_good_candidate(rr, rt) and conf >= 0.86 and len(rt) >= 16:
                break

        best_initial = max(candidates, key=lambda c: score_result(c[0], c[1]))
        best_initial_conf = candidate_confidence(best_initial[0])
        if (
            (not is_good_candidate(best_initial[0], best_initial[1]))
            or len(best_initial[1]) < 16
            or best_initial_conf < 0.82
        ):
            fallback_views = []
            if screen_roi is not None:
                bx0, by0, bx1, by1 = screen_roi["bbox"]
                if (bx1 - bx0) >= 16 and (by1 - by0) >= 16:
                    fallback_views.append(("bbox", img[by0:by1, bx0:bx1]))
            fallback_views.append(("full", img))

            for view_name, view_img in fallback_views:
                if view_img is None or view_img.size == 0:
                    continue
                v_gray = cv2.cvtColor(view_img, cv2.COLOR_BGR2GRAY)
                v_mask = build_text_mask(v_gray)
                v_roi = find_text_roi(v_mask)
                view_rois = []
                if v_roi is not None:
                    vx0, vy0, vx1, vy1, clipped = v_roi
                    view_rois.append((vx0, vy0, vx1, vy1))
                    if clipped:
                        vh, vw = view_img.shape[:2]
                        view_rois.append((0, max(0, vy0), vw, min(vh, vy1)))
                view_rois.extend(propose_bright_text_rois(view_img, max_rois=3))
                view_rois = dedupe_rois(view_rois, iou_threshold=0.62, max_rois=3)
                if not view_rois:
                    view_rois = [(0, 0, view_img.shape[1], view_img.shape[0])]

                for fidx, (vx0, vy0, vx1, vy1) in enumerate(view_rois[:2]):
                    crop = view_img[vy0:vy1, vx0:vx1]
                    rr, rt = run_ocr_on_crop(reader, crop, allow_bin_fallback=True, max_passes=3)
                    candidates.append((rr, rt))
                    conf = candidate_confidence(rr)
                    vprint(
                        f"  FB[{view_name}:{fidx}] "
                        f"conf={conf:.3f} score={score_result(rr, rt):.1f}"
                    )
                    if conf < 0.80 or len(normalize_candidate_text(rt)) < 16:
                        for ang in (-5, 5):
                            rot_crop = ocr_mod.rotate_crop(crop, ang)
                            rr_rot, rt_rot = run_ocr_on_crop(
                                reader, rot_crop, allow_bin_fallback=False, max_passes=2
                            )
                            candidates.append((rr_rot, rt_rot))
                            conf_rot = candidate_confidence(rr_rot)
                            vprint(
                                f"  FB[{view_name}:{fidx}@{ang}] "
                                f"conf={conf_rot:.3f} score={score_result(rr_rot, rt_rot):.1f}"
                            )

        if not any(normalize_candidate_text(text) for (_, text) in candidates):
            direct_views = [("work", work_img), ("full", img)]
            for view_name, view_img in direct_views:
                if view_img is None or view_img.size == 0:
                    continue
                rr = read_text(reader, view_img)
                rt = combine_tokens(rr)
                candidates.append((rr, rt))
                conf = candidate_confidence(rr)
                vprint(
                    f"  FB[direct:{view_name}] "
                    f"conf={conf:.3f} score={score_result(rr, rt):.1f}"
                )

        consensus_text, _ = select_consensus_candidate(candidates)
        results, combined = choose_reliable_result(candidates)

        if consensus_text:
            combined_norm = normalize_candidate_text(combined)
            consensus_norm = normalize_candidate_text(consensus_text)
            if consensus_norm:
                cluster_match = False
                max_dist = 2 if max(len(combined_norm), len(consensus_norm)) <= 18 else 3
                if combined_norm and abs(len(combined_norm) - len(consensus_norm)) <= max_dist:
                    dist = ocr_mod.bounded_levenshtein(combined_norm, consensus_norm, max_dist)
                    cluster_match = dist <= max_dist
                if cluster_match or not combined_norm:
                    combined = consensus_norm

        if combined:
            combined = normalize_ocr_ambiguities(best_text_window(combined))

        matched_pw = None
        for pw in EXPECTED:
            if combined == pw:
                matched_pw = pw
                break
        if matched_pw is not None:
            correct += 1
        status = "OK" if matched_pw else "FAIL"
        if matched_pw:
            print(f"[{status}] {fname}: '{combined}'")
        else:
            print(f"[{status}] {fname}: '{combined}' (no match)")
        print()

    print(f"\n{'='*60}")
    print(f"Results: {correct}/{total} correct")
    if correct == total:
        print("ALL PASS")
    else:
        print(f"{total - correct} FAILED")


if __name__ == "__main__":
    main()
