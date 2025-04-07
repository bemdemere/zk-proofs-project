# write unit tests for the client.py file
# test the following functions:
    # compute_user_hash
    # generate_graph
    # compute_graph_hash
    # generate_zksnark_inputs


import unittest
from client.client import compute_user_hash, generate_graph, compute_graph_hash, generate_zksnark_inputs

class TestClient(unittest.TestCase):
    def test_compute_user_hash(self):
        self.assertEqual(compute_user_hash("alice", "mypassword1234", "random_salt"), "b4b2d24e9f9b15b0d49b2")     
        self.assertEqual(compute_user_hash("bob", "password", "salt"), "c5d4d24e9f9b15b0d49b2")
        self.assertEqual(compute_user_hash("charlie", "password123", "random"), "b4b2d24e9f9b15b0d49b2")
    
    def test_generate_graph(self):
        user_hash = "b4b2d24e9f9b15b0d49b2"
        N_base = 10
        G, colors = generate_graph(user_hash, N_base)
        self.assertEqual(len(G.nodes()), 15)
        self.assertEqual(len(G.edges()), 16)
        self.assertEqual(colors[0], 1)
        self.assertEqual(colors[1], 2)
        self.assertEqual(colors[2], 0)
        self.assertEqual(colors[3], 1)
        self.assertEqual(colors[4], 0)
        self.assertEqual(colors[5], 2)
        self.assertEqual(colors[6], 1)
        self.assertEqual(colors[7], 2)
        self.assertEqual(colors[8], 0)
        self.assertEqual(colors[9], 1)
        self.assertEqual(colors[10], 2)
        self.assertEqual(colors[11], 0)
        self.assertEqual(colors[12], 1)
        self.assertEqual(colors[13], 2)
        self.assertEqual(colors[14], 0)

    def test_compute_graph_hash(self):
        user_hash = "b4b2d24e9f9b15b0d49b2"
        N_base = 10
        G, colors = generate_graph(user_hash, N_base)
        self.assertEqual(compute_graph_hash(G), "f9b15b0d49b2b4b2d24e9")

