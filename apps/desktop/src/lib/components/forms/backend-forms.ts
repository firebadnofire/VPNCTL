import WireGuardForm from "./WireGuardForm.svelte";
import AmneziaWgForm from "./AmneziaWgForm.svelte";
import OpenVpnForm from "./OpenVpnForm.svelte";
import Ikev2Form from "./Ikev2Form.svelte";
import XrayForm from "./XrayForm.svelte";

export const backendForms = {
  wireguard: WireGuardForm,
  amnezia_wg: AmneziaWgForm,
  openvpn: OpenVpnForm,
  ikev2: Ikev2Form,
  xray: XrayForm,
};
