#!/usr/bin/env python3
"""
IronKey GUI - GTK4 Interface for IronKey S200

Requires: python3-gi, gir1.2-gtk-4.0
"""

import os
import sys
import threading
import logging
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from openironkey.scsi.ironkey_scsi import IronKeySCSI, find_ironkey_device
from openironkey.cli.ironkey_cli import IronKeyCLI
from openironkey.applet.ironkey_applet import IronKeyAppletManager, KNOWN_APPLETS

try:
    import gi
    gi.require_version('Gtk', '4.0')
    gi.require_version('Adw', '1')
    from gi.repository import Gtk, GLib, Adw, Gio
    GTK_AVAILABLE = True
except ImportError:
    GTK_AVAILABLE = False

logger = logging.getLogger(__name__)

class IronKeyWindow(Adw.ApplicationWindow):
    def __init__(self, app, device_path: str):
        super().__init__(application=app)
        self.device_path = device_path
        self.cli = None
        self.applet_manager = None
        self.unlock_thread = None
        
        self.set_title("IronKey S200 Control Panel")
        self.set_default_size(800, 600)
        
        self.build_ui()
        self.refresh_status()
    
    def build_ui(self):
        # Main layout
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.set_content(main_box)
        
        # Header bar
        header = Adw.HeaderBar()
        header.set_title_widget(Gtk.Label(label="IronKey S200"))
        main_box.append(header)
        
        # Content
        content = Adw.ToolbarView()
        main_box.append(content)
        
        # Top toolbar with status
        top_toolbar = Adw.ToolbarView()
        content.add_top_bar(top_toolbar)
        
        status_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        status_box.set_margin_top(12)
        status_box.set_margin_bottom(12)
        status_box.set_margin_start(12)
        status_box.set_margin_end(12)
        top_toolbar.set_content(status_box)
        
        # Device info
        self.device_label = Gtk.Label(label="Device: Detecting...")
        self.device_label.set_xalign(0)
        status_box.append(self.device_label)
        
        self.status_label = Gtk.Label(label="Status: Unknown")
        self.status_label.set_xalign(1)
        status_box.append(self.status_label)
        
        # Main content area with sidebar
        self.main_content = Adw.NavigationView()
        content.set_content(self.main_content)
        
        # Sidebar
        sidebar = Adw.NavigationPage()
        sidebar.set_title("IronKey")
        sidebar.set_icon_name("drive-removable-media-symbolic")
        
        sidebar_list = Gtk.ListBox()
        sidebar_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        sidebar.set_child(sidebar_list)
        
        # Navigation items
        nav_items = [
            ("drive-harddisk-symbolic", "Device", "device"),
            ("preferences-system-symbolic", "Security", "security"),
            ("package-x-generic-symbolic", "Applets", "applets"),
            ("preferences-desktop-symbolic", "Settings", "settings"),
        ]
        
        self.nav_pages = {}
        for icon, label, page_id in nav_items:
            row = Adw.ActionRow()
            row.set_title(label)
            row.add_prefix(Gtk.Image.new_from_icon_name(icon))
            row.set_activatable(True)
            row.connect("activated", self.on_nav_activated, page_id)
            sidebar_list.append(row)
            self.nav_pages[page_id] = row
        
        self.main_content.push_by_tag("device")
        
        # Device page
        device_page = self.create_device_page()
        self.main_content.add(device_page, "device")
        
        # Security page
        security_page = self.create_security_page()
        self.main_content.add(security_page, "security")
        
        # Applets page
        applets_page = self.create_applets_page()
        self.main_content.add(applets_page, "applets")
        
        # Settings page
        settings_page = self.create_settings_page()
        self.main_content.add(settings_page, "settings")
    
    def create_device_page(self) -> Adw.NavigationPage:
        page = Adw.NavigationPage()
        page.set_title("Device")
        page.set_tag("device")
        
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        page.set_child(scrolled)
        
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(12)
        box.set_margin_end(12)
        scrolled.set_child(box)
        
        # Device info group
        group = Adw.PreferencesGroup(title="Device Information")
        box.append(group)
        
        self.info_vendor = Adw.EntryRow(title="Vendor")
        self.info_vendor.set_editable(False)
        group.add(self.info_vendor)
        
        self.info_product = Adw.EntryRow(title="Product")
        self.info_product.set_editable(False)
        group.add(self.info_product)
        
        self.info_revision = Adw.EntryRow(title="Revision")
        self.info_revision.set_editable(False)
        group.add(self.info_revision)
        
        self.info_serial = Adw.EntryRow(title="Serial Number")
        self.info_serial.set_editable(False)
        group.add(self.info_serial)
        
        # Status group
        status_group = Adw.PreferencesGroup(title="Status")
        box.append(status_group)
        
        self.status_locked = Adw.SwitchRow(title="Locked")
        self.status_locked.set_active(True)
        self.status_locked.set_sensitive(False)
        status_group.add(self.status_locked)
        
        # Actions group
        actions_group = Adw.PreferencesGroup(title="Actions")
        box.append(actions_group)
        
        refresh_btn = Gtk.Button(label="Refresh Status")
        refresh_btn.connect("clicked", self.on_refresh)
        actions_group.add(refresh_btn)
        
        return page
    
    def create_security_page(self) -> Adw.NavigationPage:
        page = Adw.NavigationPage()
        page.set_title("Security")
        page.set_tag("security")
        
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        page.set_child(scrolled)
        
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(12)
        box.set_margin_end(12)
        scrolled.set_child(box)
        
        # Unlock group
        unlock_group = Adw.PreferencesGroup(title="Unlock Device")
        box.append(unlock_group)
        
        self.pin_entry = Adw.PasswordEntryRow(title="PIN")
        self.pin_entry.set_show_apply_button(True)
        self.pin_entry.connect("apply", self.on_unlock)
        unlock_group.add(self.pin_entry)
        
        self.unlock_btn = Gtk.Button(label="Unlock")
        self.unlock_btn.add_css_class("suggested-action")
        self.unlock_btn.connect("clicked", self.on_unlock)
        unlock_group.add(self.unlock_btn)
        
        self.lock_btn = Gtk.Button(label="Lock Device")
        self.lock_btn.connect("clicked", self.on_lock)
        unlock_group.add(self.lock_btn)
        
        # PIN management
        pin_group = Adw.PreferencesGroup(title="PIN Management")
        box.append(pin_group)
        
        self.change_pin_btn = Gtk.Button(label="Change PIN")
        self.change_pin_btn.connect("clicked", self.on_change_pin)
        pin_group.add(self.change_pin_btn)
        
        return page
    
    def create_applets_page(self) -> Adw.NavigationPage:
        page = Adw.NavigationPage()
        page.set_title("Applets")
        page.set_tag("applets")
        
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        page.set_child(scrolled)
        
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(12)
        box.set_margin_end(12)
        scrolled.set_child(box)
        
        # Applet list
        group = Adw.PreferencesGroup(title="Available Applets")
        box.append(group)
        
        self.applet_list = Gtk.ListBox()
        self.applet_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        group.add(self.applet_list)
        
        # Populate applets
        for name, info in KNOWN_APPLETS.items():
            row = Adw.ActionRow()
            row.set_title(name)
            row.set_subtitle(info['description'])
            row.add_suffix(Gtk.Button(label="Launch", callback=self.on_launch_applet, data=name))
            self.applet_list.append(row)
        
        return page
    
    def create_settings_page(self) -> Adw.NavigationPage:
        page = Adw.NavigationPage()
        page.set_title("Settings")
        page.set_tag("settings")
        
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        page.set_child(scrolled)
        
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(12)
        box.set_margin_end(12)
        scrolled.set_child(box)
        
        group = Adw.PreferencesGroup(title="Application Settings")
        box.append(group)
        
        self.auto_unlock = Adw.SwitchRow(title="Auto-unlock on insert")
        group.add(self.auto_unlock)
        
        self.minimize_tray = Adw.SwitchRow(title="Minimize to tray")
        group.add(self.minimize_tray)
        
        return page
    
    def on_nav_activated(self, row, page_id):
        self.main_content.push_by_tag(page_id)
    
    def on_refresh(self, button):
        self.refresh_status()
    
    def refresh_status(self):
        """Refresh device status in background"""
        def worker():
            try:
                with IronKeySCSI(self.device_path) as dev:
                    info = dev.inquiry()
                    vendor = info[8:16].decode().strip()
                    product = info[16:32].decode().strip()
                    revision = info[32:36].decode().strip()
                    
                    GLib.idle_add(self.update_device_info, vendor, product, revision)
            except Exception as e:
                GLib.idle_add(self.update_device_info, "Error", str(e), "")
        
        threading.Thread(target=worker, daemon=True).start()
    
    def update_device_info(self, vendor, product, revision):
        self.info_vendor.set_text(vendor)
        self.info_product.set_text(product)
        self.info_revision.set_text(revision)
        self.device_label.set_label(f"Device: {self.device_path}")
        return False
    
    def on_unlock(self, widget):
        pin = self.pin_entry.get_text()
        if not pin:
            self.show_error("Please enter a PIN")
            return
        
        self.unlock_btn.set_sensitive(False)
        self.pin_entry.set_sensitive(False)
        
        def worker():
            try:
                with IronKeySCSI(self.device_path) as dev:
                    success = dev.unlock(pin)
                    GLib.idle_add(self.unlock_finished, success)
            except Exception as e:
                GLib.idle_add(self.unlock_finished, False, str(e))
        
        self.unlock_thread = threading.Thread(target=worker, daemon=True)
        self.unlock_thread.start()
    
    def unlock_finished(self, success, error=None):
        self.unlock_btn.set_sensitive(True)
        self.pin_entry.set_sensitive(True)
        
        if success:
            self.status_locked.set_active(False)
            self.show_info("Device unlocked successfully!")
        else:
            self.show_error(f"Unlock failed: {error or 'Unknown error'}")
    
    def on_lock(self, button):
        # Lock implementation
        self.status_locked.set_active(True)
        self.show_info("Device locked (SCSI lock not fully implemented)")
    
    def on_change_pin(self, button):
        dialog = Adw.MessageDialog(
            heading="Change PIN",
            body="PIN change functionality requires SCSI protocol completion.",
        )
        dialog.add_response("ok", "OK")
        dialog.set_default_response("ok")
        dialog.set_close_response("ok")
        dialog.present(self)
    
    def on_launch_applet(self, button, applet_name):
        def worker():
            try:
                manager = IronKeyAppletManager()
                proc = manager.launch_applet(applet_name)
                proc.wait()
                GLib.idle_add(self.show_info, f"{applet_name} exited with code {proc.returncode}")
            except Exception as e:
                GLib.idle_add(self.show_error, f"Failed to launch: {e}")
        
        threading.Thread(target=worker, daemon=True).start()
    
    def show_info(self, message):
        dialog = Adw.MessageDialog(
            heading="Information",
            body=message,
        )
        dialog.add_response("ok", "OK")
        dialog.set_default_response("ok")
        dialog.set_close_response("ok")
        dialog.present(self)
    
    def show_error(self, message):
        dialog = Adw.MessageDialog(
            heading="Error",
            body=message,
        )
        dialog.add_response("ok", "OK")
        dialog.set_default_response("ok")
        dialog.set_close_response("ok")
        dialog.present(self)


class IronKeyApplication(Adw.Application):
    def __init__(self, device_path: str):
        super().__init__(application_id="com.ironkey.controlpanel")
        self.device_path = device_path
    
    def do_activate(self):
        window = IronKeyWindow(self, self.device_path)
        window.present()


def main():
    if not GTK_AVAILABLE:
        print("GTK4 not available. Install python3-gi and gir1.2-gtk-4.0")
        return 1
    
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--device', help='SCSI device path')
    parser.add_argument('--verbose', '-v', action='store_true')
    args = parser.parse_args()
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    
    device = args.device or find_ironkey_device()
    if not device:
        print("No IronKey device found")
        return 1
    
    app = IronKeyApplication(device)
    return app.run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())