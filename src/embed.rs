//! Puts the window of an outside program (Remotedesktop, PuTTY, a VNC viewer) inside an
//! AdminCraft tab, the way mRemoteNG does it: the program's main window becomes a child
//! window of ours and follows the tab's position and size.
//!
//! Windows only. Elsewhere the program keeps its own window and the tab shows its state.

/// Physical pixel rectangle inside our window's client area.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PxRect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

#[cfg(windows)]
mod imp {
    use super::PxRect;
    use std::sync::atomic::{AtomicIsize, Ordering};
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
    use windows_sys::Win32::Graphics::Gdi::*;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetFocus, SetFocus};
    use windows_sys::Win32::UI::WindowsAndMessaging::*;

    /// The embedded window shown in the active tab (0 = none).
    static ACTIVE: AtomicIsize = AtomicIsize::new(0);
    static OLD_PROC: AtomicIsize = AtomicIsize::new(0);
    static HOOKED: AtomicIsize = AtomicIsize::new(0);

    pub fn set_active(h: isize) {
        ACTIVE.store(h, Ordering::Relaxed);
    }

    fn is_inside(win: HWND, parent: HWND) -> bool {
        !win.is_null() && (win == parent || unsafe { IsChild(parent, win) } != 0)
    }

    /// Our window's message handler in front of winit's: a click into an embedded window
    /// gives it the keyboard (like mRemoteNG), a click on AdminCraft itself takes it back.
    unsafe extern "system" fn parent_proc(h: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
        let old: WNDPROC = std::mem::transmute(OLD_PROC.load(Ordering::Relaxed));
        let active = ACTIVE.load(Ordering::Relaxed) as HWND;
        match msg {
            WM_PARENTNOTIFY if !active.is_null() => {
                let ev = (wp & 0xFFFF) as u32;
                if ev == WM_LBUTTONDOWN || ev == WM_RBUTTONDOWN || ev == WM_MBUTTONDOWN {
                    let pt = POINT { x: (lp & 0xFFFF) as i16 as i32, y: ((lp >> 16) & 0xFFFF) as i16 as i32 };
                    let child = ChildWindowFromPointEx(h, pt, CWP_SKIPINVISIBLE);
                    if child == active && !is_inside(GetFocus(), active) {
                        SetFocus(active);
                    }
                }
            }
            WM_LBUTTONDOWN | WM_RBUTTONDOWN | WM_MBUTTONDOWN => {
                if GetFocus() != h {
                    SetFocus(h);
                }
            }
            WM_ACTIVATE if !active.is_null() && (wp & 0xFFFF) as u32 == WA_ACTIVE => {
                let r = CallWindowProcW(old, h, msg, wp, lp);
                SetFocus(active);
                return r;
            }
            _ => {}
        }
        CallWindowProcW(old, h, msg, wp, lp)
    }

    pub fn install_focus_hook(parent: isize) {
        if HOOKED.swap(parent, Ordering::SeqCst) == parent {
            return;
        }
        unsafe {
            let old = SetWindowLongPtrW(parent as HWND, GWLP_WNDPROC, parent_proc as *const () as isize);
            OLD_PROC.store(old, Ordering::SeqCst);
        }
    }

    /// Picture of part of our window as the screen shows it (embedded windows included).
    pub fn capture(parent: isize, r: PxRect) -> Option<(usize, usize, Vec<u8>)> {
        if r.w <= 0 || r.h <= 0 {
            return None;
        }
        unsafe {
            let mut pt = POINT { x: r.x, y: r.y };
            ClientToScreen(parent as HWND, &mut pt);
            let screen = GetDC(std::ptr::null_mut());
            let mem = CreateCompatibleDC(screen);
            let bmp = CreateCompatibleBitmap(screen, r.w, r.h);
            let old = SelectObject(mem, bmp as HGDIOBJ);
            BitBlt(mem, 0, 0, r.w, r.h, screen, pt.x, pt.y, SRCCOPY | CAPTUREBLT);
            SelectObject(mem, old);
            let mut info: BITMAPINFO = std::mem::zeroed();
            info.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
            info.bmiHeader.biWidth = r.w;
            info.bmiHeader.biHeight = -r.h; // top-down
            info.bmiHeader.biPlanes = 1;
            info.bmiHeader.biBitCount = 32;
            info.bmiHeader.biCompression = BI_RGB;
            let mut buf = vec![0u8; (r.w * r.h * 4) as usize];
            let lines = GetDIBits(mem, bmp, 0, r.h as u32, buf.as_mut_ptr() as *mut _, &mut info, DIB_RGB_COLORS);
            DeleteObject(bmp as HGDIOBJ);
            DeleteDC(mem);
            ReleaseDC(std::ptr::null_mut(), screen);
            if lines == 0 {
                return None;
            }
            for px in buf.chunks_exact_mut(4) {
                px.swap(0, 2); // BGRA -> RGBA
                px[3] = 255;
            }
            Some((r.w as usize, r.h as usize, buf))
        }
    }

    pub struct Embedded {
        pub pid: u32,
        class_hint: &'static [&'static str],
        hwnd: HWND,
        attached: bool,
        visible: bool,
        had_focus: bool,
        last: PxRect,
        original_style: isize,
    }

    // HWND is a plain handle; the window lives in another process.
    unsafe impl Send for Embedded {}

    struct Search {
        pid: u32,
        hints: &'static [&'static str],
        best: HWND,
        best_score: i64,
    }

    fn class_name(h: HWND) -> String {
        let mut buf = [0u16; 128];
        let n = unsafe { GetClassNameW(h, buf.as_mut_ptr(), buf.len() as i32) };
        String::from_utf16_lossy(&buf[..n.max(0) as usize])
    }

    unsafe extern "system" fn enum_cb(h: HWND, lp: LPARAM) -> i32 {
        let s = &mut *(lp as *mut Search);
        let mut pid = 0u32;
        GetWindowThreadProcessId(h, &mut pid);
        if pid != s.pid || IsWindowVisible(h) == 0 {
            return 1;
        }
        let class = class_name(h);
        if class.starts_with("IME") || class == "MSCTFIME UI" {
            return 1;
        }
        // with a known main window class, dialogs (certificate warning, "connecting...") stay
        // floating; without one, a dialog-based program may still be its own main window
        let dialog = class == "#32770";
        if dialog && !s.hints.is_empty() {
            return 1;
        }
        let mut r: RECT = std::mem::zeroed();
        GetWindowRect(h, &mut r);
        let (w, hgt) = ((r.right - r.left) as i64, (r.bottom - r.top) as i64);
        let area = w.max(0) * hgt.max(0);
        let mut score = area;
        if s.hints.iter().any(|c| class.eq_ignore_ascii_case(c)) {
            score += 1 << 40;
        }
        if score > s.best_score && w >= 300 && hgt >= 200 {
            s.best_score = score;
            s.best = h;
        }
        1
    }

    impl Embedded {
        pub fn new(pid: u32, class_hint: &'static [&'static str]) -> Self {
            Embedded {
                pid,
                class_hint,
                hwnd: std::ptr::null_mut(),
                attached: false,
                visible: false,
                had_focus: false,
                last: PxRect::default(),
                original_style: 0,
            }
        }

        pub fn attached(&self) -> bool {
            self.attached && unsafe { IsWindow(self.hwnd) != 0 }
        }

        pub fn handle(&self) -> isize {
            if self.attached() {
                self.hwnd as isize
            } else {
                0
            }
        }

        pub fn lost(&self) -> bool {
            self.attached && unsafe { IsWindow(self.hwnd) == 0 }
        }

        /// Looks for the program's main window and takes it in. `parent` is our HWND.
        pub fn try_attach(&mut self, parent: isize) -> bool {
            if self.attached {
                return true;
            }
            let mut s = Search { pid: self.pid, hints: self.class_hint, best: std::ptr::null_mut(), best_score: 0 };
            unsafe {
                EnumWindows(Some(enum_cb), &mut s as *mut Search as LPARAM);
            }
            // only the hinted class counts when a hint is given (mstsc first shows other windows)
            if s.best.is_null() || (!self.class_hint.is_empty() && s.best_score < (1 << 40)) {
                return false;
            }
            let parent = parent as HWND;
            unsafe {
                // our window must not paint over its children
                let ps = GetWindowLongPtrW(parent, GWL_STYLE);
                SetWindowLongPtrW(parent, GWL_STYLE, ps | WS_CLIPCHILDREN as isize);
                let h = s.best;
                let style = GetWindowLongPtrW(h, GWL_STYLE);
                self.original_style = style;
                let remove = (WS_CAPTION | WS_THICKFRAME | WS_POPUP | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU) as isize;
                SetWindowLongPtrW(h, GWL_STYLE, (style & !remove) | WS_CHILD as isize);
                // clicks inside must reach our window as WM_PARENTNOTIFY (focus on click)
                let ex = GetWindowLongPtrW(h, GWL_EXSTYLE);
                SetWindowLongPtrW(h, GWL_EXSTYLE, ex & !(WS_EX_NOPARENTNOTIFY as isize));
                SetParent(h, parent);
                self.hwnd = h;
            }
            self.attached = true;
            // it is still showing where the program put it: the next place() moves or hides it
            self.visible = true;
            self.last = PxRect::default();
            true
        }

        /// Shows the window at `rect` (physical pixels in our client area) or hides it.
        pub fn place(&mut self, rect: Option<PxRect>) {
            if !self.attached() {
                return;
            }
            unsafe {
                match rect {
                    Some(r) if r.w > 20 && r.h > 20 => {
                        // programs sometimes move or resize themselves (centering dialogs, saved
                        // window sizes): compare with where the window really is
                        let mut cur: RECT = std::mem::zeroed();
                        GetWindowRect(self.hwnd, &mut cur);
                        let mut pts = [POINT { x: cur.left, y: cur.top }, POINT { x: cur.right, y: cur.bottom }];
                        MapWindowPoints(std::ptr::null_mut(), GetParent(self.hwnd), pts.as_mut_ptr(), 2);
                        let actual = PxRect { x: pts[0].x, y: pts[0].y, w: pts[1].x - pts[0].x, h: pts[1].y - pts[0].y };
                        if r != self.last || !self.visible || actual != r {
                            SetWindowPos(self.hwnd, std::ptr::null_mut(), r.x, r.y, r.w, r.h, SWP_NOZORDER | SWP_FRAMECHANGED | SWP_NOACTIVATE | SWP_SHOWWINDOW);
                            self.last = r;
                        }
                        if !self.visible {
                            ShowWindow(self.hwnd, SW_SHOW);
                            self.visible = true;
                            // it had the keyboard before a menu covered it: give it back
                            if self.had_focus {
                                SetFocus(self.hwnd);
                                self.had_focus = false;
                            }
                        }
                    }
                    _ => {
                        if self.visible {
                            self.had_focus = is_inside(GetFocus(), self.hwnd);
                            ShowWindow(self.hwnd, SW_HIDE);
                            self.visible = false;
                        }
                    }
                }
            }
        }

        pub fn focus(&self) {
            if self.attached() {
                unsafe {
                    SetFocus(self.hwnd);
                }
            }
        }

        /// Gives the window back as a normal window of its own.
        pub fn detach(&mut self) {
            if !self.attached() {
                self.attached = false;
                return;
            }
            unsafe {
                SetParent(self.hwnd, std::ptr::null_mut());
                SetWindowLongPtrW(self.hwnd, GWL_STYLE, self.original_style | WS_VISIBLE as isize);
                SetWindowPos(self.hwnd, HWND_TOP, 80, 80, self.last.w.max(800), self.last.h.max(600), SWP_FRAMECHANGED | SWP_SHOWWINDOW);
                ShowWindow(self.hwnd, SW_SHOW);
            }
            self.attached = false;
        }

        pub fn close(&mut self) {
            if self.attached() {
                unsafe {
                    PostMessageW(self.hwnd, WM_CLOSE, 0, 0);
                }
            }
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::PxRect;

    pub struct Embedded {
        pub pid: u32,
    }

    pub fn set_active(_h: isize) {}
    pub fn install_focus_hook(_parent: isize) {}
    pub fn capture(_parent: isize, _r: PxRect) -> Option<(usize, usize, Vec<u8>)> {
        None
    }

    impl Embedded {
        pub fn new(pid: u32, _class_hint: &'static [&'static str]) -> Self {
            Embedded { pid }
        }
        pub fn attached(&self) -> bool {
            false
        }
        pub fn handle(&self) -> isize {
            0
        }
        pub fn lost(&self) -> bool {
            false
        }
        pub fn try_attach(&mut self, _parent: isize) -> bool {
            false
        }
        pub fn place(&mut self, _rect: Option<PxRect>) {}
        pub fn focus(&self) {}
        pub fn detach(&mut self) {}
        pub fn close(&mut self) {}
    }
}

pub use imp::{capture, install_focus_hook, set_active, Embedded};

/// Can this system put other programs' windows into tabs?
pub const SUPPORTED: bool = cfg!(windows);

/// Our window handle as a number (Windows HWND), when there is one.
pub fn parent_handle(frame: &eframe::Frame) -> Option<isize> {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    let h = frame.window_handle().ok()?;
    match h.as_raw() {
        RawWindowHandle::Win32(w) => Some(w.hwnd.get()),
        _ => None,
    }
}
