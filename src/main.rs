// #![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use crate::{logic::kenjector::{Access, KenjectionInfo, Kenjector, ProcessInfo}, ui::{listview::{GenericListView, ListRow}, messagebox::message_box}};
use gtk4::prelude::*;
use parking_lot::RwLock;
use std::{path::PathBuf, sync::Arc};
use winapi::um::processthreadsapi::GetCurrentProcess;
mod logic;
mod ui;

const APP_NAME: &str = "Kenjector";

#[derive(Clone, Default)]
pub struct AppState {
  pub consts: AppConsts,
}

#[derive(Clone)]
pub struct AppConsts {
  pub app_name: String,
  pub upad: u32,
  pub ipad: i32,
  pub margin: i32,
  pub btn_w: i32,
  pub btn_h: i32,
}

impl Default for AppConsts {
  fn default() -> Self { return Self { app_name: String::from(APP_NAME), upad: 10, ipad: 10, margin: 20, btn_w: 80, btn_h: 30 }; }
}

pub trait MarginAll {
  fn set_margin_all(&self, margin: i32);
}

// 2) Implement it for every type that implements `IsA<Widget>`
impl<T: IsA<gtk4::Widget>> MarginAll for T {
  fn set_margin_all(&self, margin: i32) {
    self.set_margin_start(margin);
    self.set_margin_end(margin);
    self.set_margin_top(margin);
    self.set_margin_bottom(margin);
  }
}

impl ListRow for ProcessInfo {
  fn column_types() -> &'static [gtk4::glib::Type] { &[gtk4::glib::Type::OBJECT, gtk4::glib::Type::STRING, gtk4::glib::Type::STRING, gtk4::glib::Type::STRING, gtk4::glib::Type::U64, gtk4::glib::Type::STRING] }
  fn fill_row(store: &gtk4::ListStore, p: &Self) {
    let icon: Option<gtk4::gdk::Paintable> = p.icon.clone();
    let elev_dsply = if p.elevated { "  Yes" } else { "  No" };
    store.insert_with_values(None, &[(0, &icon), (1, &elev_dsply), (2, &p.name), (3, &p.arch.to_string()), (4, &p.process_id), (5, &format!("{:#X}", p.process_id))]);
  }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let application = gtk4::Application::builder().build();
  let aps = Arc::new(RwLock::new(AppState::default()));
  let consts = aps.read().consts.clone();

  application.connect_activate(move |app| {
    // dark mode
    gtk4::Settings::default().expect("Failed to get settings").set_gtk_application_prefer_dark_theme(true);

    // Add CSS
    let provider = gtk4::CssProvider::new();
    let css_bytes = include_bytes!("ui/gtk.css");
    let css_gbytes = gtk4::glib::Bytes::from(&css_bytes[..]);
    provider.load_from_bytes(&css_gbytes);

    gtk4::StyleContext::add_provider_for_display(&gtk4::gdk::Display::default().unwrap(), &provider, gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION);

    // Main window
    let window = gtk4::ApplicationWindow::new(app);
    window.set_title(Some(&consts.app_name));
    window.set_default_size(550, 700);
    window.set_resizable(true);

    // Grid container with spacing
    let grid = gtk4::Grid::new();
    grid.set_row_spacing(10);
    grid.set_column_spacing(10);
    grid.set_margin_all(consts.margin);
    window.set_child(Some(&grid));

    let kenjector = Kenjector::new();

    let mut listview = GenericListView::<ProcessInfo>::new();
    let alignment = gtk4::pango::Alignment::Left;
    listview
      .add_icon_column("Icon", 0, Some(40))
      .add_text_column("Admin", 1, Some(50), alignment)
      .add_text_column("Name", 2, Some(400), alignment)
      .add_text_column("Arch", 3, None, alignment)
      .add_text_column("ID", 4, None, alignment)
      .add_text_column("0xID", 5, None, alignment)
      .enable_sorting(4, gtk4::SortType::Ascending)
      .set_row_mapper(ProcessInfo::fill_row);

    let proc_info_vec = kenjector.get_processes();

    listview.set_items(&proc_info_vec);

    grid.attach(&listview.container, 0, 0, 2, 2);

    let input = gtk4::Entry::new();
    input.set_placeholder_text(Some("Path"));
    input.set_hexpand(true);
    // input.set_sensitive(false);

    let input_c = input.clone();
    let window_c = window.clone();

    let browse_btn = gtk4::Button::with_label("Browse");
    browse_btn.connect_clicked(move |_| {
      let dialog = gtk4::FileChooserNative::new(Some("Pick a file or folder"), Some(&window_c), gtk4::FileChooserAction::Open, Some("Select"), Some("Cancel"));

      dialog.set_select_multiple(false);

      let input_c_c = input_c.clone();
      let window_c_c = window_c.clone();
      dialog.connect_response(move |dialog, resp| {
        let kenjector = Kenjector::new();

        if resp == gtk4::ResponseType::Accept {
          if let Some(file) = dialog.file() {
            if let Some(path) = file.path() {
              match kenjector.is_pe_dll(&path) {
                Ok(v) => {
                  if v {
                    input_c_c.set_text(path.to_str().unwrap_or_default());
                  } else {
                    message_box(&window_c_c, "Failed", "The chosen file is not a dll", None);
                  }
                }
                Err(e) => message_box(&window_c_c, "Failed", format!("The chosen file is not a dll, {}", e), None),
              };
            }
          }
        }
        dialog.destroy();
      });

      dialog.show();
    });

    grid.attach(&input, 0, 2, 1, 1);
    grid.attach(&browse_btn, 1, 2, 1, 1);

    let refresh_btn = gtk4::Button::with_label("Refresh");
    {
      let kenjector_c = kenjector.clone();
      let listview_c = listview.clone();
      refresh_btn.connect_clicked(move |_| {
        let proc_info_vec = kenjector_c.get_processes();
        listview_c.set_items(&proc_info_vec);
      });
    }

    let listview_c = listview.clone();
    let input_c = input.clone();
    let window_c = window.clone();

    let inject_btn = gtk4::Button::with_label("Kenject");
    inject_btn.connect_clicked(move |_| {
      let selected_iters = listview_c.get_selected();
      let mut process_id = u64::MAX;
      let mut process_name = String::new();
      for iter in selected_iters {
        let name: gtk4::glib::Value = listview_c.list_store.get(&iter, 2);
        let value: gtk4::glib::Value = listview_c.list_store.get(&iter, 4);

        process_name = name.get().unwrap();
        // println!("{}{}", "process name = ", process_name);
        let data: u64 = value.get().unwrap();
        process_id = data;
        // println!("Selected data: {}", data);
      }

      let process_id = process_id as u32;
      let kenjection_info = KenjectionInfo { name: process_name.clone(), process_id };
      let path = PathBuf::from(input_c.text());

      // Verify the file is a valid PE DLL
      let path_valid = match kenjector.is_pe_dll(&path) {
        Ok(true) => true,
        Ok(false) => {
          message_box(&window_c, "Failed", "The chosen file is not a DLL", None);
          false
        }
        Err(e) => {
          message_box(&window_c, "Failed", e.to_string(), None);
          false
        }
      };

      if path_valid {
        if !kenjector.is_elevated(unsafe { GetCurrentProcess() }).unwrap() {
          match kenjector.open_process(Access::Limited, process_id) {
            Ok(process_handle) => {
              if let Ok(true) = kenjector.is_elevated(process_handle) {
                return;
              }
            }
            Err(_) => {
              message_box(&window_c, "Kenjection failed", "Can't Kenject into an elevated process without running as admin", None);
              return;
            }
          };
        }

        match kenjector.kennject(&kenjection_info, path.clone()) {
          Ok(v) => message_box(&window_c, "Kenjection complete", &format!("Kenjected into {}\n{}", process_name, v), None),
          Err(e) => message_box(&window_c, "Kenjection failed", &format!("Failed to Kennject into {}\n{}", process_name, e), None),
        }
      }
    });

    grid.attach(&inject_btn, 0, 3, 1, 1);
    grid.attach(&refresh_btn, 1, 3, 1, 1);

    window.present();
  });

  application.run();
  Ok(())
}
