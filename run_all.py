from __future__ import annotations

import argparse
from pathlib import Path
import sys
import time

STEPS_DIR = Path(__file__).resolve().parent / "steps"
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from url_detector.common import setup_logger
from steps.step_01_collection import run_collection, find_raw_directory
from steps.step_02_parsing import run_parsing
from steps.step_03_normalize import run_normalize
from steps.step_04_clean import run_clean
from steps.step_05_features import run_features
from steps.step_06_dataset import run_dataset_split
from steps.step_07_train import run_train
from steps.step_08_evaluate import run_evaluate

logger = setup_logger("QuyTrinh-Steps")

def run_pipeline(
    sample_size: int = 5000,
    input_source: str = None,
    dataset_path: str = None,
    target_step: str = "all",
) -> None:
    t_start = time.time()
    s_label = f"{sample_size:,}" if sample_size else "toan bo"
    print(f"Chay quy trinh AIC211 (mau: {s_label})")

    if target_step == "1":
        print("\n> Buoc 01: Kiem tra nguon du lieu raw")
        run_collection(input_path=input_source, sample_size=sample_size)

    if target_step in ("all", "2"):
        print("\n> Buoc 02: Tien xu ly URL truc tiep tu raw")
        run_parsing(input_path=input_source, max_samples=sample_size)

    if target_step in ("all", "3"):
        print("\n> Buoc 03: Chuan hoa")
        run_normalize(max_samples=sample_size)

    if target_step in ("all", "4"):
        print("\n> Buoc 04: Lam sach")
        run_clean(max_samples=sample_size)

    if target_step in ("all", "5"):
        print("\n> Buoc 05: Trich xuat dac trung")
        run_features(max_samples=sample_size)

    if target_step in ("all", "6"):
        print("\n> Buoc 06: Chia dataset")
        run_dataset_split(input_file=dataset_path, max_samples=sample_size)

    if target_step in ("all", "7"):
        print("\n> Buoc 07: Huan luyen mo hinh")
        run_train(samples=sample_size)

    if target_step in ("all", "8"):
        print("\n> Buoc 08: Danh gia mo hinh")
        run_evaluate(samples=sample_size)

    elapsed = round(time.time() - t_start, 2)
    print(f"\nHoan tat trong {elapsed}s.")

def interactive_menu():
    while True:
        print("\nQuy trinh AIC211:")
        print("  1. Buoc 01: Thu thap du lieu (Collection)")
        print("  2. Buoc 02: Tien xu ly tu raw (Parsing)")
        print("  3. Buoc 03: Chuan hoa du lieu (Normalize)")
        print("  4. Buoc 04: Lam sach du lieu (Clean)")
        print("  5. Buoc 05: Trich xuat dac trung (Features)")
        print("  6. Buoc 06: Chia tap du lieu (Train/Val/Test)")
        print("  7. Buoc 07: Huan luyen mo hinh (Train Models)")
        print("  8. Buoc 08: Danh gia mo hinh (Evaluate Models)")
        print("  9. Chay toan bo quy trinh (Run All)")
        print("  0. Thoat")

        choice = input("Chon [0-9]: ").strip()
        if choice == "0":
            break
        elif choice == "1":
            from steps.step_01_collection import prompt_menu_input
            src, s_cnt = prompt_menu_input()
            run_collection(input_path=src, sample_size=s_cnt)
        elif choice == "2":
            from steps.step_02_parsing import prompt_menu_input as p_p
            in_f, out_f, w, s_cnt = p_p()
            run_parsing(input_path=in_f, output_file=out_f, workers=w, max_samples=s_cnt)
        elif choice == "3":
            from steps.step_03_normalize import prompt_menu_input as p_n
            in_f, out_f, w, s_cnt = p_n()
            run_normalize(input_file=in_f, output_file=out_f, workers=w, max_samples=s_cnt)
        elif choice == "4":
            from steps.step_04_clean import prompt_menu_input as p_c
            in_f, out_f, rej_f, s_cnt = p_c()
            run_clean(input_file=in_f, output_file=out_f, rejected_file=rej_f, max_samples=s_cnt)
        elif choice == "5":
            from steps.step_05_features import prompt_menu_input as p_f
            in_f, out_f, w, s_cnt = p_f()
            run_features(input_file=in_f, output_file=out_f, workers=w, max_samples=s_cnt)
        elif choice == "6":
            from steps.step_06_dataset import prompt_menu_input as p_ds
            in_f, tr, vr, te, s_cnt = p_ds()
            run_dataset_split(input_file=in_f, train_ratio=tr, val_ratio=vr, test_ratio=te, max_samples=s_cnt)
        elif choice == "7":
            from steps.step_07_train import prompt_menu_input as p_tr
            in_f, out_d, mdl, s_cnt = p_tr()
            run_train(input_file=in_f, output_dir=out_d, model_choice=mdl, samples=s_cnt)
        elif choice == "8":
            from steps.step_08_evaluate import prompt_menu_input as p_ev
            in_f, mdl, s_cnt = p_ev()
            run_evaluate(test_file=in_f, model_name=mdl, samples=s_cnt)
        elif choice == "9":
            def_dir = str(find_raw_directory())
            ans_src = input(f"Duong dan raw [Enter={def_dir}]: ").strip()
            target_src = ans_src if ans_src else def_dir

            print("1. 5,000 dong (mac dinh)")
            print("2. 50,000 dong")
            print("3. Toan bo du lieu")
            print("4. Nhap so luong tuy y")
            ans_cnt = input("Chon [1-4, Enter=1]: ").strip()
            if ans_cnt == "2":
                total_s = 50000
            elif ans_cnt == "3":
                total_s = None
            elif ans_cnt == "4":
                custom = input("Nhap so dong: ").strip()
                total_s = int(custom) if custom.isdigit() else 5000
            else:
                total_s = 5000

            run_pipeline(sample_size=total_s, input_source=target_src, target_step="all")
        else:
            print("Lua chon khong hop le.")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        interactive_menu()
    else:
        parser = argparse.ArgumentParser(description="Chay quy trinh AIC211")
        parser.add_argument("-i", "--input", type=str, default=None, help="Tep du lieu hoac thu muc raw")
        parser.add_argument("-s", "--samples", type=str, default="5000", help="So luong dong mau")
        parser.add_argument("--all", action="store_true", help="Lay toan bo du lieu")
        parser.add_argument("--dataset", type=str, default=None, help="Tep dataset CSV")
        parser.add_argument("--step", type=str, default="all", choices=["all", "1", "2", "3", "4", "5", "6", "7", "8"], help="Chon buoc")
        args = parser.parse_args()

        if args.all or str(args.samples).lower() in ("0", "all", "none"):
            s_size = None
        else:
            try:
                s_size = int(args.samples)
            except ValueError:
                s_size = 5000

        run_pipeline(
            sample_size=s_size,
            input_source=args.input,
            dataset_path=args.dataset,
            target_step=args.step,
        )
