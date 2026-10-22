# Stage 2 fixtures

T12, citation laundering: the email steers the answer (G2) while telling the model not to cite it, so a warning computed from citations alone misses it. Each attack has a control with the same cover text and no instruction.

Kept apart from `fixtures/own/`, which five Stage 1 evaluations read and is frozen.

    python -m eval.run_goals --source fixtures --fixtures fixtures/stage2 \
        --goal G2 --with-cited-only --split dev --out results/stage2_dev.csv
