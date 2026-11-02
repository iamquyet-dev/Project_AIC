from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from steps.step_07_train import run_train
from steps.step_08_evaluate import run_evaluate

def main_interactive():
    print("\nBuoc 07: Mo hinh may hoc (Machine Learning)")
    print("1. Huan luyen toan bo ca 3 mo hinh (Train All Models - Mac dinh)")
    print("2. Danh gia ca 3 mo hinh (Evaluate All Models)")
    print("3. Chay ca hai: Huan luyen ca 3 mo hinh roi Danh gia ngay")
    print("4. Chon 1 mo hinh cu the de huan luyen")
    print("0. Thoat")

    choice = input("Chon [0-4, Enter=1]: ").strip()
    if choice == "0":
        return
    elif choice == "2":
        from steps.step_08_evaluate import prompt_menu_input as p_eval
        in_f, mdl, smp = p_eval()
        run_evaluate(test_file=in_f, model_name=mdl, samples=smp)
    elif choice == "3":
        from steps.step_07_train import prompt_menu_input as p_train
        in_f, out_d, mdl, smp, inc = p_train()
        run_train(input_file=in_f, output_dir=out_d, model_choice=mdl, samples=smp, is_incremental=inc)
        print("\nChuyen sang buoc danh gia mo hinh:")
        from steps.step_08_evaluate import prompt_menu_input as p_eval
        in_f_ev, mdl_ev, smp_ev = p_eval()
        run_evaluate(test_file=in_f_ev, model_name=mdl_ev, samples=smp_ev)
    elif choice == "4":
        from steps.step_07_train import prompt_menu_input as p_train
        in_f, out_d, mdl, smp, inc = p_train()
        run_train(input_file=in_f, output_dir=out_d, model_choice=mdl, samples=smp, is_incremental=inc)
    else:
        from steps.step_07_train import prompt_menu_input as p_train
        in_f, out_d, _, smp, inc = p_train()
        run_train(input_file=in_f, output_dir=out_d, model_choice="all", samples=smp, is_incremental=inc)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        main_interactive()
    else:
        parser = argparse.ArgumentParser(description="Buoc 07: Mo hinh may hoc (Train hoac Evaluate)")
        parser.add_argument("--action", choices=["train", "eval", "both"], default="train", help="Hanh dong")
        parser.add_argument("-i", "--input", default=None, help="Tep dau vao")
        parser.add_argument("-m", "--model", default="all", help="Ten mo hinh")
        parser.add_argument("-s", "--samples", type=int, default=None, help="So luong mau")
        parser.add_argument("--incremental", action="store_true", help="Hoc tang tien tiep tuc")
        args = parser.parse_args()

        if args.action == "train":
            run_train(input_file=args.input, model_choice=args.model, samples=args.samples, is_incremental=args.incremental)
        elif args.action == "eval":
            run_evaluate(test_file=args.input, model_name=args.model, samples=args.samples)
        else:
            run_train(input_file=args.input, model_choice=args.model, samples=args.samples, is_incremental=args.incremental)
            run_evaluate(test_file=None, model_name=args.model, samples=args.samples)
