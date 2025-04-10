import { initialize } from "zokrates-js";

const source = `
  import "hashes/sha256/512bitPacked" as sha256packed;
  def main(private field[4] hash_input, field[2] stored_hash) {
      field[2] computed = sha256packed(hash_input);
      assert(computed[0] == stored_hash[0]);
      assert(computed[1] == stored_hash[1]);
  }
`;

const encodeToFieldArray512bits = async (str) => {
  const padded = new Uint8Array(64);
  const bytes = new TextEncoder().encode(str);
  padded.set(bytes.slice(0, 64));
  return Array.from({ length: 4 }, (_, i) => {
    const chunk = padded.slice(i * 16, (i + 1) * 16);
    const hex = Array.from(chunk).map(b => b.toString(16).padStart(2, "0")).join("");
    return BigInt("0x" + hex);
  });
};

const hashAsFields = async (fields) => {
  const bytes = new Uint8Array(64);
  fields.forEach((f, i) => {
    const hex = f.toString(16).padStart(32, "0");
    hex.match(/.{2}/g).forEach((b, j) => {
      bytes[i * 16 + j] = parseInt(b, 16);
    });
  });
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return [
    BigInt("0x" + Array.from(hash.slice(0, 16)).map(b => b.toString(16).padStart(2, "0")).join("")),
    BigInt("0x" + Array.from(hash.slice(16)).map(b => b.toString(16).padStart(2, "0")).join(""))
  ];
};

const run = async () => {
  const zokratesProvider = await initialize();

  console.log("Compiling circuit...");
  const artifacts = zokratesProvider.compile(source);
  console.log("Artifacts:", artifacts);

  console.log("Setting up keypair...");
  const keypair = zokratesProvider.setup(artifacts.program);
  //console.log("Keypair:", JSON.stringify(keypair, null, 2));

  const preimage = "test:pass:salt|edge|color";
  const hashInput = await encodeToFieldArray512bits(preimage);
  const storedHash = await hashAsFields(hashInput);
  const inputs = [hashInput.map(x => x.toString()), storedHash.map(x => x.toString())];
  console.log("Inputs:", JSON.stringify(inputs, null, 2));

  console.log("Computing witness...");
  const { witness } = zokratesProvider.computeWitness(artifacts, inputs);
  console.log("Witness:", witness);

  console.log("Generating proof...");
  const proof = zokratesProvider.generateProof(artifacts.program, witness, keypair.pk);
  console.log("Proof:", JSON.stringify(proof, null, 2));

  const fullProof = {
    scheme: "g16",
    curve: "bn128",
    proof: proof, // Raw proof { a, b, c }
    inputs: storedHash.map(x => x.toString()) // Public inputs only
  };
  console.log("Full Proof:", JSON.stringify(fullProof, null, 2));

  console.log("Verifying proof...");
  const isValid = zokratesProvider.verify(keypair.vk, proof);
  console.log("✅ Proof valid?", isValid);
};

run().catch(console.error);