"""
Week 3 — Generates an actual ERD (Entity Relationship Diagram) image using
Graphviz, for both the normalization-demo schema and the Quizeers app's
real schema (User/Quiz/Question/Answer/Result/QuestionAttempt).
"""
import os
import graphviz

HERE = os.path.dirname(os.path.abspath(__file__))


def erd_normalization_demo():
    g = graphviz.Digraph("orders_3nf", format="png")
    g.attr(rankdir="LR", fontname="Helvetica")
    g.attr("node", shape="record", fontname="Helvetica", fontsize="10")

    g.node("customers", "{customers_3nf|customer_id (PK)\\lcustomer_name\\lcustomer_city\\l}")
    g.node("orders", "{orders_3nf|order_id (PK)\\lcustomer_id (FK)\\l}")
    g.node("items", "{order_items_3nf|order_id (PK, FK)\\lproduct (PK)\\lquantity\\l}")

    g.edge("orders", "customers", label="many-to-one")
    g.edge("items", "orders", label="many-to-one")

    out_path = os.path.join(HERE, "erd_orders_3nf")
    g.render(out_path, cleanup=True)
    print(f"wrote {out_path}.png")


def erd_quizeers_schema():
    g = graphviz.Digraph("quizeers_schema", format="png")
    g.attr(rankdir="LR", fontname="Helvetica")
    g.attr("node", shape="record", fontname="Helvetica", fontsize="10")

    g.node("user", "{User|id (PK)\\lemail\\lpassword_hash\\lis_admin\\l}")
    g.node("quiz", "{Quiz|id (PK)\\ltitle\\lcategory\\ldifficulty\\l}")
    g.node("question", "{Question|id (PK)\\lquiz_id (FK)\\ltext\\lcorrect_answer\\l}")
    g.node("answer", "{Answer|id (PK)\\lquestion_id (FK)\\ltext\\lletter\\l}")
    g.node("result", "{Result|id (PK)\\luser_id (FK)\\lquiz_id (FK)\\lscore\\l}")
    g.node("qa", "{QuestionAttempt|id (PK)\\lresult_id (FK)\\luser_id (FK)\\lquiz_id (FK)\\lquestion_id (FK)\\lchosen_answer\\lis_correct\\l}")

    g.edge("quiz", "question", label="1-to-many")
    g.edge("question", "answer", label="1-to-many")
    g.edge("user", "result", label="1-to-many")
    g.edge("quiz", "result", label="1-to-many")
    g.edge("result", "qa", label="1-to-many")
    g.edge("question", "qa", label="1-to-many")

    out_path = os.path.join(HERE, "erd_quizeers_schema")
    g.render(out_path, cleanup=True)
    print(f"wrote {out_path}.png")


if __name__ == "__main__":
    erd_normalization_demo()
    erd_quizeers_schema()
