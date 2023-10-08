import hashlib

class Block:
    def __init__(self, sender, receiver, amount, prev_hash=""):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.prev_hash = prev_hash
        self.nonce = 0
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        data = (
            str(self.nonce) +
            "Sender:" + self.sender +
            "Receiver:" + self.receiver +
            "Amount:" + str(self.amount) +
            "Previous Hash:" + self.prev_hash
        )
        return hashlib.sha256(data.encode()).hexdigest()

    def mine_block(self, difficulty):
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()

    def __str__(self):
        return (
            "NONCE =" + str(self.nonce) + "\n" +
            "Sender:" + self.sender + "\n" +
            "Receiver:" + self.receiver + "\n" +
            "Amount:" + str(self.amount) + "\n" +
            "Previous Hash:" + self.prev_hash
        )

class Blockchain:
    def __init__(self, difficulty):
        self.difficulty = difficulty
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block(sender="Genesis", receiver="Genesis", amount=0)

    def add_block(self, sender, receiver, amount):
        prev_block = self.chain[-1]
        new_block = Block(sender, receiver, amount, prev_block.hash)
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)

    def display_chain(self):
        for block in self.chain:
            print(str(block))
            print("Block Hash:", block.hash)
            print()

if __name__ == "__main__":
    difficulty = 4
    blockchain = Blockchain(difficulty)

    blockchain.add_block("c", "b", 123)
    blockchain.add_block("a", "b", 12)
    blockchain.add_block("atha", "bhwe", 69.420)
    blockchain.add_block("abgwajg", "bgeragew", 0.343)

    blockchain.display_chain()
