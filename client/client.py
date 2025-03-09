import hashlib
import random
import networkx as nx

# Compute Hash of (Username + Password + Salt) ===
def compute_user_hash(username, password, salt):
    """Computes a deterministic hash from user credentials."""
    data = f"{username}:{password}:{salt}".encode()
    return hashlib.sha256(data).hexdigest()

#  Generate a 3-Colorable Graph ===
def generate_graph(user_hash, N_base=10):
    """Generates a deterministic 3-colorable graph from a hashed seed."""
    random.seed(int(user_hash[:16], 16))  # Use first 16 hex chars as randomness
    
    N = N_base + len(user_hash) % 10  # Scale graph size
    G = nx.Graph()

    # Assign nodes to three color groups
    colors = {i: random.randint(0, 2) for i in range(N)}

    # Add edges ensuring 3-colorability
    for i in range(N):
        for j in range(i + 1, N):
            if colors[i] != colors[j] and random.random() < 0.4:  # 40% chance of 
                G.add_edge(i, j)

    return G, colors

# Compute H(G) (Hash of Graph Structure) ===
def compute_graph_hash(G):
    """Hashes the graph edges deterministically to store as H(G)."""
    graph_str = "".join(sorted(f"{u}-{v}" for u, v in G.edges()))
    return hashlib.sha256(graph_str.encode()).hexdigest()

# Generate zk-SNARK Inputs ===
def generate_zksnark_inputs(username, password, salt):
    """Creates zk-SNARK inputs from user credentials."""
    user_hash = compute_user_hash(username, password, salt)
    G, colors = generate_graph(user_hash)
    graph_hash = compute_graph_hash(G)  # This is H(G), stored on server
    
    return {
        "graph": G,
        "graph_edges": list(G.edges()),
        "coloring": colors,  # Prover keeps this secret
        "user_hash": user_hash,  # Used as zk-SNARK input
        "graph_hash": graph_hash  # Stored publicly on the server
    }


# Testing the above functions

username = "alice"
password = "mypassword1234"
salt = "random_salt"

zk_inputs = generate_zksnark_inputs(username, password, salt)

print("\nzk-SNARK Inputs Ready!")
print(f"User Hash (Secret Input): {zk_inputs['user_hash']}")
print(f"Public Graph Hash H(G): {zk_inputs['graph_hash']}")
print(f"Graph Edges (Public): {zk_inputs['graph_edges']}")
print(f"Graph Coloring (Private, known only to prover): {zk_inputs['coloring']}")

def is_3_colorable(G):
    """Checks if the given graph is 3-colorable using NetworkX."""
    coloring = nx.coloring.greedy_color(G, strategy="largest_first")
    
    # Get the number of unique colors used
    num_colors = len(set(coloring.values()))
    
    # If the number of colors used is ≤ 3, the graph is 3-colorable
    return num_colors <= 3, coloring

print("\nChecking if Graph is 3-Colorable...")
is_colorable, coloring = is_3_colorable(zk_inputs['graph'])
print(f"Graph is 3-Colorable: {is_colorable}")
print(f"Coloring: {coloring}")