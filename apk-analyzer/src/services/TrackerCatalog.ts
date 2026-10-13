export interface TrackerDefinition { id: string; vendor: string; purpose: string; }
export const TRACKER_CATALOG: TrackerDefinition[] = [
  { id: 'com.facebook.appevents', vendor: 'Meta', purpose: 'analytics and advertising measurement' },
  { id: 'com.google.android.gms.measurement', vendor: 'Google', purpose: 'analytics and advertising measurement' },
  { id: 'com.google.firebase.analytics', vendor: 'Google Firebase', purpose: 'product analytics' },
  { id: 'com.adjust', vendor: 'Adjust', purpose: 'mobile attribution and analytics' },
  { id: 'com.localytics', vendor: 'Localytics', purpose: 'product analytics and engagement' },
  { id: 'com.flurry', vendor: 'Flurry', purpose: 'mobile analytics and advertising' },
  { id: 'com.mixpanel', vendor: 'Mixpanel', purpose: 'product analytics' },
  { id: 'com.amplitude', vendor: 'Amplitude', purpose: 'product analytics' },
  { id: 'com.appsflyer', vendor: 'AppsFlyer', purpose: 'mobile attribution and analytics' },
  { id: 'com.crashlytics', vendor: 'Google Firebase', purpose: 'crash reporting' },
  { id: 'com.bytedance.applog', vendor: 'ByteDance', purpose: 'analytics and attribution' },
];
export const trackerDefinition = (id: string) => TRACKER_CATALOG.find(t => t.id === id);
