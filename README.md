# Frida_Binder_Hook
It's Analyze the Frida Code about Binder_Hook

As I thought, it seems to be the most complex and most useful code in the Native level among the codes that were composed through Frida. We analyze this and practice hooking the native level later

the original is : https://github.com/Hamz-a/frida-android-libbinder


## The Reason for hooking binder
Android uses Binder for inter-process communications and that it might be a good place for malware to eavesdrop for sensitive information.
