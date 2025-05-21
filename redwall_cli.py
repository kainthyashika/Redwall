import pyfiglet
import datetime
import random

def show_banner():
    banner = pyfiglet.figlet_format("RedWall", font="slant")
    print("=" * 160)
    print(banner)
    print("     Context-Aware Cyber Defense CLI Tool")
    print("=" * 60)

def get_input(prompt, options):
    while True:
        val = input(prompt).strip()
        if val in options:
            return val
        else:
            print(f"Invalid input. Please choose from: {', '.join(options)}")

def compute_risk_score(role, context, device, region, mfa):
    score = 0
    score += {"Admin": 10, "User": 30, "Guest": 50}.get(role, 50)
    score += {"Secure Network": 10, "VPN": 20, "Unsecure Network": 40, "Public WiFi": 50}.get(context, 50)
    score += {"Trusted": 10, "Unknown": 30, "Compromised": 50}.get(device, 50)
    score += {"India": 10, "USA": 15, "Russia": 35, "China": 40, "Other": 25}.get(region, 25)
    if not mfa:
        score += 30
    score += random.randint(-5, 5)
    return min(100, max(0, score))

def access_decision(score):
    if score < 40:
        return "Access Granted"
    elif score < 70:
        return "Access Limited"
    else:
        return "Access Denied"

def main():
    show_banner()

    role = get_input("Enter your role (Admin/User/Guest): ", ["Admin", "User", "Guest"])
    context = get_input("Enter network context (Secure Network/VPN/Unsecure Network/Public WiFi): ",
                        ["Secure Network", "VPN", "Unsecure Network", "Public WiFi"])
    device = get_input("Enter device trust (Trusted/Unknown/Compromised): ",
                       ["Trusted", "Unknown", "Compromised"])
    region = get_input("Enter region (India/USA/Russia/China/Other): ",
                       ["India", "USA", "Russia", "China", "Other"])
    mfa_input = input("Did the user pass MFA? (yes/no): ").strip().lower()
    mfa = mfa_input == "yes"
    ip = input("Enter user IP address: ").strip() or "127.0.0.1"

    score = compute_risk_score(role, context, device, region, mfa)
    decision = access_decision(score)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n====== RedWall Decision Report ======")
    print(f"Time: {timestamp}")
    print(f"Role: {role}")
    print(f"Network: {context}")
    print(f"Device Trust: {device}")
    print(f"Region: {region}")
    print(f"MFA Passed: {mfa}")
    print(f"IP Address: {ip}")
    print(f"Risk Score: {score}")
    print(f"Access Decision: {decision}")

    if decision == "Access Denied":
        print(f"\n** ALERT: High Risk Access Attempt from {ip} **")

if __name__ == "__main__":
    main()
