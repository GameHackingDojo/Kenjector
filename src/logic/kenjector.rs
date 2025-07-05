use derive_more::Display;
use gtk4::{gdk::prelude::DisplayExt, prelude::NativeExt};
use pelite::{FileMap, pe32::{Pe as Pe32, PeFile as Pe32File}, pe64::{Pe as Pe64, PeFile as Pe64File}};
use std::{ffi::{CStr, CString}, path::PathBuf};
use winapi::{shared::windef::{HBITMAP, HICON}, um::{handleapi::CloseHandle, libloaderapi::{GetModuleHandleA, GetProcAddress}, memoryapi::{VirtualAllocEx, WriteProcessMemory}, processthreadsapi::{CreateRemoteThread, GetExitCodeThread, OpenProcess, OpenProcessToken}, psapi::GetModuleFileNameExW, securitybaseapi::GetTokenInformation, shellapi::ExtractIconExW, synchapi::WaitForSingleObject, tlhelp32::{CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, Process32Next, TH32CS_SNAPPROCESS}, winbase::INFINITE, wingdi::{BITMAPINFO, BITMAPINFOHEADER, DIB_RGB_COLORS, DeleteDC, DeleteObject, GetDIBits}, winnt::{HANDLE, IMAGE_FILE_MACHINE_I386, MEM_COMMIT, PAGE_READWRITE, PROCESS_ALL_ACCESS, PROCESS_QUERY_LIMITED_INFORMATION, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation}, winuser::{GetIconInfo, ICONINFO}, wow64apiset::IsWow64Process2}};

#[derive(Debug, Clone, Display)]
#[display("{} - {:#X}", name, process_id)]
pub struct ProcessInfo {
  pub icon: Option<gtk4::gdk::Paintable>,
  pub elevated: bool,
  pub name: String,
  pub arch: Arch,
  pub process_id: u32,
}

#[derive(Debug, Clone, Display)]
#[display("{} - {:#X}", name, process_id)]
pub struct KenjectionInfo {
  pub name: String,
  pub process_id: u32,
}

#[derive(Debug, Default)]
struct VersionInfo {
  product_version: String,
  legal_copyright: String,
  original_filename: String,
  file_description: String,
  internal_name: String,
  company_name: String,
  file_version: String,
  product_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display)]
pub enum Arch {
  AMDx64,
  AMDx86,
  Arm64,
  Unknown,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display)]
pub enum Access {
  Full = PROCESS_ALL_ACCESS,
  Limited = PROCESS_QUERY_LIMITED_INFORMATION,
}

#[derive(Debug, Copy, Clone)]
pub struct Kenjector {}
impl Kenjector {
  pub fn kennject(kenjection_info: &KenjectionInfo, path: PathBuf) -> Result<String, String> {
    let process_id = Self::get_pid(&kenjection_info.name).map_err(|e| format!("Failed to get PID: {}", e))?;
    let dll_str = path.to_str().ok_or("Invalid DLL path")?;
    let dll_cstring = CString::new(dll_str).map_err(|_| "CString conversion failed")?;
    println!("DLL path being injected: {:?}", dll_cstring);

    unsafe {
      let h_process = Self::open_process(Access::Full, process_id).unwrap();
      if h_process.is_null() {
        return Err(format!("OpenProcess failed, error: {:#X?}", std::io::Error::last_os_error()));
      }

      // println!("h_process = {:X?}, process_id = {}, kenjection_info.process_id = {}, kenjection_info.name = {}", h_process, process_id, kenjection_info.process_id, kenjection_info.name);

      let alloc = VirtualAllocEx(h_process, std::ptr::null_mut(), dll_cstring.to_bytes_with_nul().len(), MEM_COMMIT, PAGE_READWRITE);

      if alloc.is_null() {
        CloseHandle(h_process);
        return Err(format!("VirtualAllocEx failed, error: {:#X?}", std::io::Error::last_os_error()));
      }

      let wrote = WriteProcessMemory(h_process, alloc, dll_cstring.as_ptr() as _, dll_cstring.to_bytes_with_nul().len(), std::ptr::null_mut());

      if wrote == 0 {
        CloseHandle(h_process);
        return Err(format!("WriteProcessMemory failed, error: {:#X?}", std::io::Error::last_os_error()));
      }

      let kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr() as _);
      let load_library = GetProcAddress(kernel32, b"LoadLibraryA\0".as_ptr() as _);
      if load_library.is_null() {
        CloseHandle(h_process);
        return Err(format!("GetProcAddress failed, error: {:#X?}", std::io::Error::last_os_error()));
      }

      let thread = CreateRemoteThread(h_process, std::ptr::null_mut(), 0, Some(std::mem::transmute(load_library)), alloc, 0, std::ptr::null_mut());

      if thread.is_null() {
        CloseHandle(h_process);
        return Err(format!("CreateRemoteThread failed, error: {:#X?}", std::io::Error::last_os_error()));
      }

      WaitForSingleObject(thread, INFINITE);

      let mut remote_result: u32 = 0;
      let got = GetExitCodeThread(thread, &mut remote_result);

      CloseHandle(thread);
      CloseHandle(h_process);

      if got == 0 {
        Ok(format!("GetExitCodeThread failed."))
      } else if remote_result == 0 {
        Ok(format!("LoadLibraryA failed — did not load DLL."))
      } else {
        Ok(format!("DLL Kenjected successfully at 0x{:X}", remote_result))
      }
    }
  }

  fn get_pid(name: &str) -> Result<u32, String> {
    unsafe {
      let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
      if snapshot == std::ptr::null_mut() {
        return Err(format!("CreateToolhelp32Snapshot failed, error: {:#X?}", std::io::Error::last_os_error()));
      }

      let mut entry: PROCESSENTRY32 = std::mem::zeroed();
      entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

      if Process32First(snapshot, &mut entry) == 0 {
        CloseHandle(snapshot);
        return Err(format!("Process32First failed, error: {:#X?}", std::io::Error::last_os_error()));
      }

      loop {
        let exe_name_cstr = CStr::from_ptr(entry.szExeFile.as_ptr());
        if let Ok(exe_name) = exe_name_cstr.to_str() {
          if exe_name.eq_ignore_ascii_case(name) {
            CloseHandle(snapshot);
            return Ok(entry.th32ProcessID);
          }
        }

        if Process32Next(snapshot, &mut entry) == 0 {
          break;
        }
      }

      CloseHandle(snapshot);
      Err("Process not found".to_string())
    }
  }

  pub fn open_process(access: Access, process_id: u32) -> Result<HANDLE, Box<dyn std::error::Error>> {
    let handle = unsafe { OpenProcess(access as u32, 0, process_id) };
    if !handle.is_null() { Ok(handle) } else { Err(format!("Failed to retrieve handle of the process, process_id {}, error: {:#X?}", process_id, std::io::Error::last_os_error()).into()) }
  }

  pub fn get_processes() -> Vec<ProcessInfo> {
    let mut processes: Vec<ProcessInfo> = Vec::new();

    unsafe {
      // Create snapshot of all processes
      let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
      if snapshot.is_null() {
        eprintln!("Error creating process snapshot, error: {:#X?}", std::io::Error::last_os_error());
        return processes;
      }

      let mut process_entry: PROCESSENTRY32 = std::mem::zeroed();
      process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

      // Get first process
      if Process32First(snapshot, &mut process_entry) == 0 {
        eprintln!("Error getting first process, error: {:#X?}", std::io::Error::last_os_error());
        return processes;
      }

      loop {
        let process_id = process_entry.th32ProcessID;
        let mut arch = Arch::Unknown;
        let mut elevated = true;

        let process = Self::open_process(Access::Limited, process_id);

        if process.is_ok() {
          let process = process.unwrap();
          elevated = match Self::is_elevated(process) {
            Ok(v) => v,
            Err(_) => true,
          };

          arch = match Self::architecture(process) {
            Ok(v) => v,
            Err(_) => Arch::Unknown,
          };
        }

        let name = CStr::from_ptr(process_entry.szExeFile.as_ptr()).to_string_lossy().into_owned();

        processes.push(ProcessInfo { icon: Self::get_process_icon(process_id), elevated, name, arch, process_id });

        // Get next process
        if Process32Next(snapshot, &mut process_entry) == 0 {
          break;
        }
      }

      // Close the snapshot handle
      winapi::um::handleapi::CloseHandle(snapshot);
    }

    processes
  }

  pub fn is_elevated(process: HANDLE) -> Result<bool, Box<dyn std::error::Error>> {
    unsafe {
      let mut token = std::ptr::null_mut();

      if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
        return Err("Failed to open process token".into());
      }

      let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
      let mut size: u32 = 0;

      let success = GetTokenInformation(token, TokenElevation, &mut elevation as *mut _ as *mut _, std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut size);

      if success == 0 {
        CloseHandle(token); // Don't forget to close the handle
        return Err("Failed to get token information".into());
      }

      CloseHandle(token);
      Ok(elevation.TokenIsElevated != 0)
    }
  }

  pub fn architecture(process: HANDLE) -> Result<Arch, Box<dyn std::error::Error>> {
    let mut process_machine = 0;
    let mut native_machine = 0;

    unsafe {
      if IsWow64Process2(process, &mut process_machine, &mut native_machine) == 0 {
        return Err("IsWow64Process2 failed".into());
      }
    }

    match (process_machine, native_machine) {
      (IMAGE_FILE_MACHINE_UNKNOWN, IMAGE_FILE_MACHINE_AMD64) => Ok(Arch::AMDx64), // 64-bit native process
      (IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64) => Ok(Arch::AMDx86),    // 32-bit on 64-bit
      (IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_I386) => Ok(Arch::AMDx86),     // 32-bit on 32-bit
      (IMAGE_FILE_MACHINE_UNKNOWN, IMAGE_FILE_MACHINE_ARM64) => Ok(Arch::Arm64),
      _ => Ok(Arch::Unknown),
    }
  }

  pub fn is_pe_dll(path: &PathBuf) -> Result<bool, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    let pe = goblin::pe::PE::parse(&bytes)?;
    Ok(pe.header.coff_header.characteristics & goblin::pe::characteristic::IMAGE_FILE_DLL != 0)
  }

  // pub fn get_version_info(path: &PathBuf) -> Result<VersionInfo, Box<dyn std::error::Error>> {
  //   let bytes = fs::read(path)?;
  //   let pe = goblin::pe::PE::parse(&bytes)?;
  //   let mut version_info = VersionInfo::default();

  //   if let Some(resources) = pe.resources {
  //     if let Some(version_info_resource) = resources.version_info {
  //       let string_file_info = version_info_resource.string_file_info;

  //       // Convert to a more convenient HashMap
  //       let info_map: DashMap<&str, &str> = string_file_info.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

  //       version_info.product_version = info_map.get("ProductVersion").map(|s| s.to_string());
  //       version_info.legal_copyright = info_map.get("LegalCopyright").map(|s| s.to_string());
  //       version_info.original_filename = info_map.get("OriginalFilename").map(|s| s.to_string());
  //       version_info.file_description = info_map.get("FileDescription").map(|s| s.to_string());
  //       version_info.internal_name = info_map.get("InternalName").map(|s| s.to_string());
  //       version_info.company_name = info_map.get("CompanyName").map(|s| s.to_string());
  //       version_info.file_version = info_map.get("FileVersion").map(|s| s.to_string());
  //       version_info.product_name = info_map.get("ProductName").map(|s| s.to_string());
  //     }
  //   }

  //   Ok(version_info)
  // }

  fn get_pe_version_info(path: PathBuf) -> Result<VersionInfo, String> {
    // Load the file into memory
    let file_map = FileMap::open(&path).expect(format!("Failed to open file map from {:?}", path).as_str());

    // First, determine if the file is 64-bit or 32-bit
    let is_x64 = if Pe64File::from_bytes(file_map.as_ref()).is_ok() { true } else { false };

    let mut version_info = VersionInfo::default();

    if is_x64 {
      // Handle PE32+ (64-bit) file
      let file_x64 = Pe64File::from_bytes(file_map.as_ref()).expect("Failed to parse PE64 file");
      let resources_x64 = file_x64.resources().expect("Failed to retrieve resources from PE64 file");
      let version_info_data_x64 = resources_x64.version_info().expect("Failed to retrieve version info data from resources");
      let file_info_x64 = version_info_data_x64.file_info().strings;

      // Fill the version_info struct based on available fields
      for (_, strings_info_x64) in file_info_x64 {
        version_info.product_version = strings_info_x64.get("ProductVersion").cloned().unwrap_or_default();
        version_info.legal_copyright = strings_info_x64.get("LegalCopyright").cloned().unwrap_or_default();
        version_info.original_filename = strings_info_x64.get("OriginalFilename").cloned().unwrap_or_default();
        version_info.file_description = strings_info_x64.get("FileDescription").cloned().unwrap_or_default();
        version_info.internal_name = strings_info_x64.get("InternalName").cloned().unwrap_or_default();
        version_info.company_name = strings_info_x64.get("CompanyName").cloned().unwrap_or_default();
        version_info.file_version = strings_info_x64.get("FileVersion").cloned().unwrap_or_default();
        version_info.product_name = strings_info_x64.get("ProductName").cloned().unwrap_or_default();
      }
    } else {
      // Handle PE32 (32-bit) file
      let file_x86 = Pe32File::from_bytes(file_map.as_ref()).expect("Failed to parse PE32 file");
      let resources_x86 = file_x86.resources().expect("Failed to retrieve resources from PE32 file");
      let version_info_data_x86 = resources_x86.version_info().expect("Failed to retrieve version info data from resources");
      let file_info_x86 = version_info_data_x86.file_info().strings;

      // Fill the version_info struct based on available fields
      for (_, strings_info_x86) in file_info_x86 {
        version_info.product_version = strings_info_x86.get("ProductVersion").cloned().unwrap_or_default();
        version_info.legal_copyright = strings_info_x86.get("LegalCopyright").cloned().unwrap_or_default();
        version_info.original_filename = strings_info_x86.get("OriginalFilename").cloned().unwrap_or_default();
        version_info.file_description = strings_info_x86.get("FileDescription").cloned().unwrap_or_default();
        version_info.internal_name = strings_info_x86.get("InternalName").cloned().unwrap_or_default();
        version_info.company_name = strings_info_x86.get("CompanyName").cloned().unwrap_or_default();
        version_info.file_version = strings_info_x86.get("FileVersion").cloned().unwrap_or_default();
        version_info.product_name = strings_info_x86.get("ProductName").cloned().unwrap_or_default();
      }
    }

    // Return the populated VersionInfo struct
    return Ok(version_info);
  }

  pub fn get_process_icon(process_id: u32) -> Option<gtk4::gdk::Paintable> {
    let process;

    match Self::open_process(Access::Full, process_id) {
      Ok(v) => process = v,
      Err(_) => return None,
    }

    match Self::get_process_hicon(process) {
      Ok(v) => Self::hicon_to_paintable(v),
      Err(_) => return None,
    }
  }

  // Retrieves the first large icon from a process's executable
  fn get_process_hicon(process: HANDLE) -> Result<winapi::shared::windef::HICON, Box<dyn std::error::Error>> {
    // Buffer for executable path (supports long paths)
    const BUF_SIZE: usize = 0x8000;
    let mut filename: [u16; BUF_SIZE] = [0; BUF_SIZE];

    // Get executable path
    let len = unsafe { GetModuleFileNameExW(process, std::ptr::null_mut(), filename.as_mut_ptr(), BUF_SIZE as u32) };

    if len == 0 {
      return Err(std::io::Error::last_os_error().into());
    }

    // Extract first large icon
    let mut large_icon: winapi::shared::windef::HICON = std::ptr::null_mut();
    let count = unsafe {
      ExtractIconExW(
        filename.as_ptr(),
        0, // First icon index
        &mut large_icon,
        std::ptr::null_mut(),
        1, // Extract only one icon
      )
    };

    match count {
      // No icons found
      0 => Err(std::io::Error::new(std::io::ErrorKind::NotFound, "No icons found in executable").into()),
      // Success
      _ if !large_icon.is_null() => Ok(large_icon),
      // Extraction failed
      _ => Err(std::io::Error::new(std::io::ErrorKind::Other, "Icon extraction failed").into()),
    }
  }

  fn hicon_to_paintable(hicon: HICON) -> Option<gtk4::gdk::Paintable> {
    unsafe {
      // 1) Retrieve ICONINFO to get the HBITMAP for color
      let mut icon_info: ICONINFO = std::mem::zeroed();
      if GetIconInfo(hicon, &mut icon_info) == 0 {
        return None;
      }
      let hbitmap: HBITMAP = icon_info.hbmColor;

      // 2) Prepare a BITMAPINFOHEADER to query dimensions/format
      let mut bmp_info_header: BITMAPINFOHEADER = std::mem::zeroed();
      bmp_info_header.biSize = size_of::<BITMAPINFOHEADER>() as u32;

      let mut bmp_info: BITMAPINFO = std::mem::zeroed();
      bmp_info.bmiHeader = bmp_info_header;

      // 3) Create a compatible DC (needed by GetDIBits)
      let hdc = winapi::um::wingdi::CreateCompatibleDC(std::ptr::null_mut());
      if hdc.is_null() {
        DeleteObject(icon_info.hbmColor as _);
        DeleteObject(icon_info.hbmMask as _);
        return None;
      }

      // 4) First call to GetDIBits with nRows = 0 to fill in bmiHeader (width/height/etc.)
      if GetDIBits(hdc, hbitmap, 0, 0, std::ptr::null_mut(), &mut bmp_info, DIB_RGB_COLORS) == 0 {
        DeleteDC(hdc);
        DeleteObject(icon_info.hbmColor as _);
        DeleteObject(icon_info.hbmMask as _);
        return None;
      }

      let width = bmp_info.bmiHeader.biWidth;
      let raw_height = bmp_info.bmiHeader.biHeight;
      let height = raw_height.abs();
      // 5) Compute row_stride for a 32-bit image (DWORD-aligned)
      let row_stride = ((width * 32 + 31) / 32) * 4;
      let image_size = (row_stride * height) as usize;

      // 6) Allocate a buffer for the pixel data
      let mut pixels = vec![0u8; image_size];

      // 7) Set negative height to request a top-down DIB
      bmp_info.bmiHeader.biHeight = -(height as i32);

      // 8) Second call to GetDIBits to actually fill our `pixels` buffer
      if GetDIBits(hdc, hbitmap, 0, height as u32, pixels.as_mut_ptr() as *mut _, &mut bmp_info, DIB_RGB_COLORS) == 0 {
        DeleteDC(hdc);
        DeleteObject(icon_info.hbmColor as _);
        DeleteObject(icon_info.hbmMask as _);
        return None;
      }

      // 9) Clean up the DC and bitmaps
      DeleteDC(hdc);
      DeleteObject(icon_info.hbmColor as _);
      DeleteObject(icon_info.hbmMask as _);

      // 10) Swap B <-> R so that BGRA becomes RGBA
      for chunk in pixels.chunks_exact_mut(4) {
        chunk.swap(0, 2);
      }

      // 11) Build a Pixbuf from the raw RGBA data
      let pixbuf = gtk4::gdk_pixbuf::Pixbuf::from_mut_slice(
        pixels,
        gtk4::gdk_pixbuf::Colorspace::Rgb,
        true, // has alpha
        8,    // bits per sample
        width,
        height,
        row_stride as i32,
      );

      // 12) Convert Pixbuf → Texture → Paintable
      Some(gtk4::gdk::Texture::for_pixbuf(&pixbuf).into())
    }
  }
}

pub struct GtkHelper {}
impl GtkHelper {
  // pub fn img_from_bytes( bytes: &[u8]) -> Result<gtk4::Image, gtk4::glib::Error> {
  //   let loader = gtk4::gdk_pixbuf::PixbufLoader::new();
  //   loader.write(bytes)?;
  //   loader.close()?;
  //   let pixbuf = loader.pixbuf().ok_or_else(|| gtk4::glib::Error::new(gtk4::gdk_pixbuf::PixbufError::Failed, "Failed to get pixbuf"))?;
  //   Ok(gtk4::Image::from_pixbuf(Some(&pixbuf)))
  // }

  pub fn monitor_info(window: &gtk4::ApplicationWindow) -> Result<gtk4::gdk::Monitor, Box<dyn std::error::Error>> {
    let display = gtk4::prelude::WidgetExt::display(window);
    // println!("Display name: {}", display.name());

    // If you need the monitor (screen) information
    if let Some(monitor) = display.monitor_at_surface(&window.surface().unwrap()) {
      Ok(monitor)
      // println!("Monitor geometry: {:?}", monitor.geometry());
      // println!("Monitor scale factor: {}", monitor.scale_factor());
      // println!("Monitor refresh rate: {}", monitor.refresh_rate());
    } else {
      Err("Failed to get monitor info".into())
    }
  }

  #[cfg(target_os = "windows")]
  pub fn get_window_dimensions(hwnd: winapi::shared::windef::HWND) -> Option<(i32, i32)> {
    let mut rect = winapi::shared::windef::RECT { left: 0, top: 0, right: 0, bottom: 0 };

    unsafe { if winapi::um::winuser::GetWindowRect(hwnd, &mut rect) != 0 { Some((rect.right - rect.left, rect.bottom - rect.top)) } else { None } }
  }

  #[cfg(target_os = "windows")]
  fn get_hwnd(window: &gtk4::ApplicationWindow) -> Option<*mut winapi::shared::windef::HWND__> {
    // Get the GDK surface

    use gtk4::{glib::object::{Cast, ObjectExt}, prelude::NativeExt};
    let surface = window.surface()?;

    // Check if this is a Win32 surface (Windows platform)
    if !surface.is::<gdk4_win32::Win32Surface>() {
      return None;
    }

    // Downcast to Win32Surface
    let win32_surface = surface.downcast::<gdk4_win32::Win32Surface>().ok()?;

    // Conversion from gdk4_win32::HWND to *mut HWND__
    let hwnd_isize = win32_surface.handle().0;
    Some(hwnd_isize as *mut _)
  }

  #[cfg(target_os = "windows")]
  pub fn centre_to_screen(window: &gtk4::ApplicationWindow) -> Result<(), Box<dyn std::error::Error>> {
    use gtk4::gdk::prelude::MonitorExt;

    let monitor = Self::monitor_info(window)?;
    let monitor_x = monitor.geometry().x();
    let monitor_y = monitor.geometry().y();
    let monitor_w = monitor.geometry().width();
    let monitor_h = monitor.geometry().height();
    let scale = monitor.scale();

    if let Some(hwnd) = Self::get_hwnd(window) {
      unsafe {
        if let Some(win_dim) = Self::get_window_dimensions(hwnd) {
          let new_x = monitor_x + ((monitor_w - win_dim.0) as f64 / 2.0 * scale) as i32;
          let new_y = monitor_y + ((monitor_h - win_dim.1) as f64 / 2.0 * scale) as i32;

          winapi::um::winuser::SetWindowPos(hwnd, winapi::um::winuser::HWND_TOP, new_x, new_y, 0, 0, winapi::um::winuser::SWP_NOSIZE);
        }
      };
    }

    Ok(())
  }
}
