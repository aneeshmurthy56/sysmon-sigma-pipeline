import os
import networkx as nx
from parse_events import get_process_creation_events

EVTX_FILE = os.path.join("samples", "attack_sample.evtx")


def build_process_graph(events):
    G = nx.DiGraph()

    for ev in events:
        p_id = ev["ParentProcessId"]
        p_img = os.path.basename(ev["ParentImage"]) if ev["ParentImage"] else "Unknown"

        c_id = ev["ProcessId"]
        c_img = os.path.basename(ev["Image"]) if ev["Image"] else "Unknown"
        cmd = ev["CommandLine"]

        # Label nodes by Process Name and PID
        parent_node = f"{p_img} ({p_id})"
        child_node = f"{c_img} ({c_id})"

        # Add nodes with metadata and connect parent -> child
        G.add_node(parent_node)
        G.add_node(child_node, image=c_img, cmd=cmd, full_path=ev["Image"])
        G.add_edge(parent_node, child_node)

    return G


def print_execution_tree(G, node, prefix=""):
    children = list(G.successors(node))
    for i, child in enumerate(children):
        is_last = (i == len(children) - 1)
        connector = "└── " if is_last else "├── "
        cmd = G.nodes[child].get("cmd", "N/A")
        print(f"{prefix}{connector}{child}")
        print(f"{prefix}{'    ' if is_last else '│   '}Command: {cmd}")
        new_prefix = prefix + ("    " if is_last else "│   ")
        print_execution_tree(G, child, new_prefix)


if __name__ == "__main__":
    events = get_process_creation_events(EVTX_FILE)
    graph = build_process_graph(events)

    print(f"Graph constructed: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} execution edges.\n")
    print("Reconstructed Attack Tree:")

    # Find root nodes (processes that launched actions but have no parent recorded in the log)
    roots = [n for n, in_degree in graph.in_degree() if in_degree == 0 and graph.out_degree(n) > 0]

    for root in roots:
        print(f"\n[Root Process] {root}")
        print_execution_tree(graph, root)