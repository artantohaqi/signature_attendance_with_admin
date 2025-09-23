import numpy as np
from fastdtw import fastdtw
from scipy.spatial.distance import euclidean
import json

def strokes_to_point_list(strokes):
    pts = []
    for stroke in strokes:
        if isinstance(stroke, dict) and 'points' in stroke:
            point_list = stroke['points']
        else:
            point_list = stroke
        for p in point_list:
            if isinstance(p, dict):
                x = float(p.get('x', 0))
                y = float(p.get('y', 0))
            else:
                x, y = float(p[0]), float(p[1])
            pts.append([x, y])
    return np.array(pts, dtype=np.float64)

def resample_points(pts, n=150):
    if pts.shape[0] == 0:
        return np.zeros((n,2), dtype=np.float64)
    d = np.linalg.norm(np.diff(pts, axis=0), axis=1)
    cum = np.concatenate(([0.0], np.cumsum(d)))
    total = cum[-1]
    if total == 0:
        return np.tile(pts[0], (n,1))
    target = np.linspace(0, total, n)
    resampled = []
    j = 0
    for t in target:
        while j < len(cum)-1 and cum[j+1] < t:
            j += 1
        if j == len(cum)-1:
            resampled.append(pts[-1])
        else:
            t0, t1 = cum[j], cum[j+1]
            p0, p1 = pts[j], pts[j+1]
            if t1 - t0 == 0:
                resampled.append(p0)
            else:
                alpha = (t - t0) / (t1 - t0)
                resampled.append(p0 + alpha * (p1 - p0))
    return np.array(resampled, dtype=np.float64)

def normalize_points(pts):
    if pts.shape[0] == 0:
        return pts
    mean = pts.mean(axis=0)
    pts = pts - mean
    max_range = max(pts[:,0].ptp(), pts[:,1].ptp(), 1e-6)
    pts = pts / max_range
    return pts

def preprocess_signature(sig_json, n=150):
    pts = strokes_to_point_list(sig_json)
    pts = resample_points(pts, n=n)
    pts = normalize_points(pts)
    return pts

def dtw_distance(a, b):
    distance, _ = fastdtw(a, b, dist=euclidean)
    norm = (a.shape[0] + b.shape[0]) / 2.0
    return distance / norm