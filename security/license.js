const LICENSE_KEY = "FREIGHTLOGIC-OPERATOR-2026";

function verifyLicense() {
  const saved = localStorage.getItem("freightlogic_license");
  if (saved === LICENSE_KEY) return true;

  const input = prompt("Enter FreightLogic License Key");
  if (input === LICENSE_KEY) {
    localStorage.setItem("freightlogic_license", input);
    return true;
  }

  alert("Invalid License");
  return false;
}

if (!verifyLicense()) {
  throw new Error("License verification failed");
}