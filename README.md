# Teamtime attendance app

A lightweight single-app web interface for administrators and employees.

The employee page provides browser-based check-in and check-out reminders using the schedule in `app.js`. Browser reminders require the app to stay open; browser system notifications also require permission. If permission was blocked, open the site controls beside the browser address bar, choose **Site settings**, change **Notifications** to **Allow**, and reload the app.

On Windows, install scheduled desktop reminders to receive check-in and check-out notifications while the browser is closed or nobody is signed in to the app:

```powershell
.\install-reminders.ps1
```

The installer reads the reminder times from `app.js` and registers tasks for the current Windows user. If Windows is signed out at a reminder time, it can show that day's missed reminder after the user signs in later that day. Windows cannot display a desktop notification while no Windows user session is active. Run `.\uninstall-reminders.ps1` to remove the scheduled tasks. Re-run the installer if you change the reminder times.

Check-in reminders repeat every minute from the scheduled local check-in time until 30 minutes have passed. If an employee still has not checked in that day, the app then opens a prompt for a reason. Submitting the reason records the check-in, and admins can review it on the Leave Requests page.

## Run locally

Requires Node.js 18 or newer. No third-party packages are needed.

```sh
npm start
```

Open [http://127.0.0.1:3000](http://127.0.0.1:3000). On first launch, create the admin username and password. Admins can then create employee accounts with an employee ID and password, or set a new password for an existing employee. Employees sign in with their employee ID and password and use the Check in / Check out button.

### Use from a phone on the same Wi-Fi

The interface adapts to phone screens. To let a phone on your trusted Wi-Fi reach the app, stop the local server and start it listening on the network:

```powershell
$env:HOST = "0.0.0.0"
npm start
```

Find this computer's private IPv4 address with `ipconfig`, then open `http://<computer-LAN-IP>:3000` on the phone. For example, if the computer's address is `192.168.1.25`, open `http://192.168.1.25:3000`. Both devices must be on the same Wi-Fi. Windows Firewall may ask whether to allow Node.js; allow access only on a trusted private network. Stop the server when phone access is no longer needed.

This app uses HTTP, not HTTPS. System notifications are therefore unavailable when opening it via its LAN address; in-app reminders still work while the page is open. Use this only on a trusted private network; do not expose it to the internet or an untrusted/public Wi-Fi network.

Employees can choose to remember their employee ID in the current browser. Passwords are never saved in the browser.

Admins can generate a one-time recovery code from the admin workspace. Save it somewhere private: the code is only displayed once, a newly generated code invalidates the previous one, and successful recovery consumes it. Use **Forgot password?** on the admin sign-in screen with the admin username, saved recovery code, and a new password. Employee password recovery is handled by an admin.

Attendance records and password hashes are saved in `store.json`. Back up this file to preserve records. Passwords are hashed with Node's scrypt; the app never stores the original password.

## Notes

This is a minimal, single-instance app intended for local use or as a starting point. Sessions are held in memory and expire after eight hours. Before exposing it to a network or using it for production records, add HTTPS, durable database backups, multi-process-safe storage, account recovery and password-change flows, and deployment-specific monitoring and access controls. Keep the data directory private.
