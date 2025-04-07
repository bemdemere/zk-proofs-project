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
    
    # If the number of colors used is <= 3, the graph is 3-colorable
    return num_colors <= 3, coloring

print("\nChecking if Graph is 3-Colorable...")
is_colorable, coloring = is_3_colorable(zk_inputs['graph'])
print(f"Graph is 3-Colorable: {is_colorable}")
print(f"Coloring: {coloring}")

def str_to_field4(preimage: str) -> list:
    """Converts a string to 512-bit padded input, split into 4 field elements."""
    b = preimage.encode()
    b = b.ljust(64, b'\x00')  # pad to 64 bytes (512 bits)
    return [int.from_bytes(b[i:i+16], 'big') for i in range(0, 64, 16)]  # 4 × 128-bit chunks

def str_to_field2(h: bytes) -> list:
    """Returns SHA256 digest of bytes split into 2 field elements."""
    return [
        int.from_bytes(h[:16], 'big'),
        int.from_bytes(h[16:], 'big')
    ]

def write_dynamic_circuit_and_inputs(zk_inputs):
    colors = zk_inputs['coloring']
    edges = zk_inputs['graph_edges']
    user_hash = zk_inputs['user_hash']
    graph_hash = zk_inputs['graph_hash']

    N = len(colors)
    M = len(edges)

    #  Generate color checks
    color_checks = "\n".join([
        f"    assert(colors[{i}] * (colors[{i}] - 1) * (colors[{i}] - 2) == 0);"
        for i in range(N)
    ])

    #  Generate edge checks
    edge_checks = "\n".join([
        f"    assert(colors[{u}] != colors[{v}]);"
        for u, v in edges
    ])

    #  Circuit template with correct hash input size (field[4])
    circuit_code = f"""
import "hashes/sha256/512bitPacked" as sha256packed;

def main(
    private field[{N}] colors,
    field[{M}][2] edges,
    private field[4] hash_input,
    field[2] stored_hash
) {{
{color_checks}

{edge_checks}

    field[2] computed_hash = sha256packed(hash_input);
    assert(computed_hash[0] == stored_hash[0]);
    assert(computed_hash[1] == stored_hash[1]);
    return;
}}
""".strip()

    with open("circuit_dynamic.zok", "w") as f:
        f.write(circuit_code)
    print(f"\nGenerated circuit_dynamic.zok with N={N}, M={M}")

    #  Write input.txt
    color_array = [colors[i] for i in sorted(colors)]
    edge_array = [e for pair in edges for e in pair]  # flatten [M][2] into list of 2*M fields
    
    preimage = f"{username}:{password}:{salt}"
    hash_input = str_to_field4(preimage)

    padded_bytes = preimage.encode().ljust(64, b'\x00')
    digest = hashlib.sha256(padded_bytes).digest()
    stored_hash = str_to_field2(digest)


    print(f"color_array: {len(color_array)}")
    print(f"edge_array: {len(edge_array)}")
    print(f"hash_input: {len(hash_input)}")
    print(f"stored_hash: {len(stored_hash)}")

    total_inputs = len(color_array + edge_array + hash_input + stored_hash)
    print(f"TOTAL INPUTS: {total_inputs}")  # should be 60

    all_inputs = color_array + edge_array + hash_input + stored_hash

    with open("input.txt", "w") as f:
        f.write(" ".join(map(str, all_inputs)) + "\n")
    print(f"Wrote input.txt with {len(color_array)} colors and {len(edges)} edges")

# Call this after running generate_zksnark_inputs
write_dynamic_circuit_and_inputs(zk_inputs)
