export interface PermissionExplanation { category: string; purpose: string; review: string; }
const CATALOG: Record<string, PermissionExplanation> = {
  CAMERA: { category: 'Camera', purpose: 'Capture photos or video when granted.', review: 'Confirm camera access matches a visible feature.' },
  RECORD_AUDIO: { category: 'Microphone', purpose: 'Record audio when granted.', review: 'Confirm recording is expected and user-initiated.' },
  ACCESS_FINE_LOCATION: { category: 'Location', purpose: 'Access precise device location when granted.', review: 'Review whether approximate or foreground-only location would suffice.' },
  ACCESS_COARSE_LOCATION: { category: 'Location', purpose: 'Access approximate device location when granted.', review: 'Confirm location is necessary for the app’s purpose.' },
  ACCESS_BACKGROUND_LOCATION: { category: 'Location', purpose: 'Continue accessing location while the app is not in use.', review: 'Treat persistent background access as a high-scrutiny capability.' },
  READ_CONTACTS: { category: 'Personal data', purpose: 'Read entries in the user’s contacts database.', review: 'Confirm the app explains why the complete contact list is needed.' },
  READ_SMS: { category: 'Messages', purpose: 'Read SMS messages when granted.', review: 'Highly sensitive; verify the app qualifies for and needs this role.' },
  SEND_SMS: { category: 'Messages', purpose: 'Send SMS messages, potentially creating charges.', review: 'Check for a user-visible, intentional messaging workflow.' },
  READ_PHONE_STATE: { category: 'Device identity', purpose: 'Access phone and cellular state; available identifiers depend on Android version.', review: 'Review whether less identifying signals can be used.' },
  READ_CALL_LOG: { category: 'Calls', purpose: 'Read the call history when granted.', review: 'Highly sensitive; confirm this is central to the app’s declared role.' },
  MANAGE_EXTERNAL_STORAGE: { category: 'Files', purpose: 'Broad access to shared storage on supported Android versions.', review: 'Prefer the Storage Access Framework or scoped media permissions.' },
  REQUEST_INSTALL_PACKAGES: { category: 'App installation', purpose: 'Request installation of other application packages.', review: 'Confirm package installation is a core, user-controlled feature.' },
  SYSTEM_ALERT_WINDOW: { category: 'Display over apps', purpose: 'Draw interface elements over other applications.', review: 'Review for clickjacking, impersonation, and clear user control.' },
};
export const explainPermission = (permission: string): PermissionExplanation => {
  const key = permission.replace(/^android\.permission\./, '');
  return CATALOG[key] || { category: permission.startsWith('android.permission.') ? 'Android capability' : 'Application-defined', purpose: 'The exact behavior depends on Android’s permission definition and the app’s code.', review: 'Confirm the declaration is necessary and inspect how it is used.' };
};
