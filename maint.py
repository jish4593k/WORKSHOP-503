import hashlib

class Block:
    def __init__(self, prev_hash, sender, receiver, amount):
        self.prev_hash = prev_hash
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.nonce = 0
        self.proof = False
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

if __name__ == "__main__":
    prev_hash = "0"  # Initial block's previous hash
    sender = "atharva"
    receiver = "rohit"
    amount = 0.123
    difficulty = 4  # Number of leading zeros for proof of work

    b = Block(prev_hash, sender, receiver, amount)
    b.mine_block(difficulty)

    print(str(b))
    print("Block Hash:", b.hash)
