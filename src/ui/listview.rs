use gtk4::prelude::*;
use std::{marker::PhantomData, sync::Arc};

/// Trait each row-type must implement to provide column schema and fill logic.
pub trait ListRow {
  /// The sequence of `glib::Type` for each column in the ListStore.
  fn column_types() -> &'static [gtk4::glib::Type];
  /// Called for each item to insert its values into the store.
  fn fill_row(store: &gtk4::ListStore, item: &Self);
}

/// A reusable GTK4 ListView component, parameterized on `T: ListRow`.
#[derive(Clone)]
pub struct GenericListView<T: ListRow> {
  pub container: gtk4::Box, // Vertical box holding everything
  pub tree_view: gtk4::TreeView,
  pub scrolled: gtk4::ScrolledWindow,
  pub search_entry: gtk4::SearchEntry,
  pub search_bar: gtk4::SearchBar,
  pub list_store: gtk4::ListStore,
  filter_model: gtk4::TreeModelFilter,
  sort_model: gtk4::TreeModelSort,
  row_mapper: Arc<dyn Fn(&gtk4::ListStore, &T)>,
  _marker: PhantomData<T>,
}

impl<T: ListRow + 'static> GenericListView<T> {
  /// Create the basic widgets and empty ListStore with the correct column types.
  pub fn new() -> Self {
    // 1) Create tree view & scroll
    let tree_view = gtk4::TreeView::builder().headers_visible(true).build();
    let scrolled = gtk4::ScrolledWindow::builder().child(&tree_view).hexpand(true).vexpand(true).build();

    // 2) Create filter/search
    let search_entry = gtk4::SearchEntry::new();
    let search_bar = gtk4::SearchBar::builder().halign(gtk4::Align::End).valign(gtk4::Align::End).show_close_button(true).child(&search_entry).build();

    // 3) Pack them into a vertical container (so search_bar overlays)
    let container = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    let overlay = gtk4::Overlay::builder().child(&scrolled).hexpand(true).vexpand(true).build();
    overlay.add_overlay(&search_bar);
    container.append(&overlay);

    // 4) Create the ListStore with T::column_types()
    let list_store = gtk4::ListStore::new(T::column_types());

    // 5) Wrap in filter + sort
    let filter_model = gtk4::TreeModelFilter::new(&list_store, None);
    let sort_model = gtk4::TreeModelSort::with_model(&filter_model);
    tree_view.set_model(Some(&sort_model));

    // 6) Filtering function
    {
      let search_entry = search_entry.downgrade();
      filter_model.set_visible_func(move |model, iter| {
        let Some(search_entry) = search_entry.upgrade() else { return false };

        let text = search_entry.text();
        if text.is_empty() {
          return true;
        }

        for i in 0..T::column_types().len() as i32 {
          if let Ok(val) = model.get_value(iter, i).get::<String>() {
            if val.to_lowercase().contains(&text.to_lowercase()) {
              return true;
            }
          }
        }
        false
      });
    }

    tree_view.set_search_entry(Some(&search_entry));

    {
      let filter_model = filter_model.downgrade();
      search_entry.connect_search_changed(move |_| {
        if let Some(filter_model) = filter_model.upgrade() {
          filter_model.refilter();
        }
      });
    }

    let key_controller = gtk4::EventControllerKey::new();
    let search_bar_c = search_bar.clone();
    key_controller.connect_key_pressed(move |_, keyval, _keycode, state| {
      // Check for Ctrl+Shift modifiers :contentReference[oaicite:0]{index=0}
      let ctrl_shift = gtk4::gdk::ModifierType::CONTROL_MASK | gtk4::gdk::ModifierType::SHIFT_MASK;
      if state.contains(ctrl_shift) && keyval == gtk4::gdk::Key::F {
        // Show the search bar and stop further propagation :contentReference[oaicite:1]{index=1}
        search_bar_c.set_search_mode(true);
        return gtk4::glib::Propagation::Stop;
      }
      // Otherwise let other handlers run :contentReference[oaicite:2]{index=2}
      gtk4::glib::Propagation::Proceed
    });

    tree_view.add_controller(key_controller);

    // 7) Default row_mapper is a no-op; user must set it before populating
    fn noop_row_mapper<T: ListRow>(_: &gtk4::ListStore, _: &T) {}
    let row_mapper = Arc::new(noop_row_mapper::<T>);

    GenericListView {
      container,
      tree_view,
      scrolled,
      search_entry,
      search_bar,
      list_store,
      filter_model,
      sort_model,
      row_mapper,
      _marker: PhantomData,
    }
  }

  /// Add a text column bound to the given model index.
  pub fn add_text_column(&mut self, title: &str, model_idx: i32, max_width: Option<i32>, alignment: gtk4::pango::Alignment) -> &mut Self {
    let renderer = gtk4::CellRendererText::new();
    // renderer.set_xalign(1.0);

    // Explicitly use the CellRendererTextExt version
    gtk4::prelude::CellRendererTextExt::set_alignment(&renderer, alignment);

    let column = gtk4::TreeViewColumn::builder().title(title).resizable(true).clickable(true).sort_column_id(model_idx).min_width(10).build();

    if let Some(w) = max_width {
      column.set_max_width(w);
      column.set_expand(true);
    }

    column.pack_start(&renderer, true);
    column.add_attribute(&renderer, "text", model_idx);
    self.tree_view.append_column(&column);

    self
  }

  pub fn add_icon_column(&mut self, title: &str, index: i32, width: Option<i32>) -> &mut Self {
    let column = gtk4::TreeViewColumn::new();
    column.set_title(title);

    let cell = gtk4::CellRendererPixbuf::new();
    column.pack_start(&cell, false);
    column.add_attribute(&cell, "gicon", index); // or "pixbuf" if using Pixbuf

    if let Some(w) = width {
      column.set_fixed_width(w);
    }

    self.tree_view.append_column(&column);

    self
  }

  /// Enable sorting by clicking headers (default descending on first column).
  pub fn enable_sorting(&mut self, default_col: u32, default_order: gtk4::SortType) -> &mut Self {
    self.sort_model.set_sort_column_id(gtk4::SortColumn::Index(default_col), default_order);
    self
  }

  /// Provide the function that maps `&T` → store-rows.
  /// Must be called before `set_items`.
  pub fn set_row_mapper<F>(&mut self, f: F) -> &mut Self
  where
    F: Fn(&gtk4::ListStore, &T) + 'static,
  {
    self.row_mapper = Arc::new(f);
    self
  }

  /// Given a slice of `T`, clear+populate the store.
  pub fn set_items(&self, items: &[T]) {
    self.list_store.clear();
    for item in items {
      (self.row_mapper)(&self.list_store, item);
    }
  }

  pub fn get_selected(&self) -> Vec<gtk4::TreeIter> {
    let selection = self.tree_view.selection();
    let (paths, _) = selection.selected_rows();
    let mut selected_iters = Vec::new();

    for path in paths {
      if let Some(sort_iter) = self.sort_model.iter(&path) {
        let filter_iter = self.sort_model.convert_iter_to_child_iter(&sort_iter);
        let list_store_iter = self.filter_model.convert_iter_to_child_iter(&filter_iter);
        selected_iters.push(list_store_iter);
      }
    }

    selected_iters
  }
}

// use gtk4::prelude::*;
// use std::{marker::PhantomData, sync::Arc};

// /// Now: each row‐type `T` must be a `glib::Object` subclass. In practice, you can:
// /// 1) derive `glib::ObjectSubclass` for your `struct T`
// /// 2) register properties or builder-data so that your `T` carries the 4 column‐values
// /// 3) implement a `fn static_type() -> glib::Type` for it (this comes for free if you derive).
// ///
// /// Then, `GenericListView<T>` will store a `gio::ListStore` of `T`‐instances,
// /// wrap it in a `FilterListModel` + `SortListModel`, and attach a `SignalListItemFactory`
// /// which, on `bind`, calls your `row_mapper(&T) -> gtk4::Widget`.
// pub struct GenericListView<T: IsA<gtk4::glib::Object>> {
//   pub container: gtk4::Box,                // vertical box holding search overlay + listview
//   pub list_view: gtk4::ListView,           // the actual ListView
//   pub scrolled: gtk4::ScrolledWindow,      // wraps list_view
//   pub search_entry: gtk4::SearchEntry,     // for filtering
//   pub search_bar: gtk4::SearchBar,         // overlays on top of scrolled
//   pub model: gtk4::gio::ListStore,         // stores T (glib::Object) instances
//   pub filter_model: gtk4::FilterListModel, // wraps `model`
//   pub sort_model: gtk4::SortListModel,     // wraps `filter_model`
//   row_mapper: Arc<dyn Fn(&T) -> gtk4::Widget>,
//   _marker: PhantomData<T>,
// }

// impl<T: IsA<gtk4::glib::Object> + 'static> GenericListView<T> {
//   /// Create a new, empty GenericListView.
//   /// You must call `set_row_mapper` before `set_items`.
//   pub fn new() -> Self {
//     // 1) create a SignalListItemFactory (we’ll hook up `bind` later)
//     let factory = gtk4::SignalListItemFactory::new();

//     // 2) create an empty `gio::ListStore` that holds items of type `T`
//     let model = gtk4::gio::ListStore::new();

//     // 3) create a FilterListModel + SortListModel around `model`
//     let filter_model = gtk4::FilterListModel::new(Some(&model), None::<&gtk4::Filter>);
//     let sort_model = gtk4::SortListModel::new(Some(&filter_model), None::<&gtk4::Sorter>);

//     // 4) create the `ListView` and point it at `sort_model` + `factory`
//     let list_view = gtk4::ListView::new(Some(&sort_model), Some(&factory));

//     // 5) wrap list_view in a ScrolledWindow, just as before
//     let scrolled = gtk4::ScrolledWindow::builder().child(&list_view).hexpand(true).vexpand(true).build();

//     // 6) create search_entry + search_bar overlay (exactly like your old code)
//     let search_entry = gtk4::SearchEntry::new();
//     let search_bar = gtk4::SearchBar::builder().halign(gtk4::Align::End).valign(gtk4::Align::End).show_close_button(true).child(&search_entry).build();

//     // 7) overlay the search_bar on top of the scrolled window
//     let container = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
//     let overlay = gtk4::Overlay::builder().child(&scrolled).hexpand(true).vexpand(true).build();
//     overlay.add_overlay(&search_bar);
//     container.append(&overlay);

//     // 8) Hook up “Ctrl+Shift+F” to pop up the search bar, same as before
//     let key_controller = gtk4::EventControllerKey::new();
//     let search_bar_clone = search_bar.clone();
//     key_controller.connect_key_pressed(move |_, keyval, _keycode, state| {
//       let ctrl_shift = gtk4::gdk::ModifierType::CONTROL_MASK | gtk4::gdk::ModifierType::SHIFT_MASK;
//       if state.contains(ctrl_shift) && keyval == gtk4::gdk::Key::F {
//         search_bar_clone.set_search_mode(true);
//         return gtk4::glib::Propagation::Stop;
//       }
//       gtk4::glib::Propagation::Proceed
//     });
//     list_view.add_controller(key_controller);

//     // 9) Filtering logic: when search text changes, update the FilterListModel
//     {
//       let filter_model_clone = filter_model.clone();
//       search_entry.connect_search_changed(move |_| {
//         // Build a new filter function each time (closure must be 'static)
//         let query = search_entry.text().to_string().to_lowercase();
//         filter_model_clone.set_filter(Some(&move |item: &gtk4::glib::Object| {
//           // `item` is a `glib::Object` which we downcast to `T`
//           if query.is_empty() {
//             return true;
//           }
//           if let Ok(row) = item.clone().downcast::<T>() {
//             // Convert your T → some searchable text. Here we assume
//             // T has a `fn to_search_text(&self) -> String` method.
//             //
//             // (You can replace this with whatever you need:
//             // maybe inspect four properties in `row` and see if any contains `query`.)
//             if let Some(searchable) = row.property::<String>("searchable") {
//               return searchable.to_lowercase().contains(&query);
//             }
//           }
//           false
//         }));
//       });
//     }

//     // 10) We still need a “default no-op” row_mapper until the user sets it
//     let noop_mapper = Arc::new(|_row: &T| -> gtk4::Widget {
//       // In case user never sets a mapper, we render an empty Label
//       gtk4::Label::new(None).upcast::<gtk4::Widget>()
//     });

//     // 11) Connect `factory` signals: `setup` builds a container for each row,
//     // and `bind` calls `row_mapper` to populate it.
//     let row_mapper_clone = noop_mapper.clone();
//     factory.connect_setup(move |_factory, list_item| {
//       // Create a placeholder container for each row (e.g. an HBox)
//       let hbox = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
//       hbox.set_margin_all(4);
//       // attach it to the list_item
//       list_item.set_child(Some(&hbox));
//     });
//     {
//       let row_mapper_clone = noop_mapper.clone();
//       factory.connect_bind(move |_factory, list_item| {
//         // Called whenever a row is about to be (re)drawn
//         let hbox = list_item.child().unwrap().downcast::<gtk4::Box>().unwrap();
//         hbox.remove_all(); // clear previous children

//         // `list_item.item()` is the `glib::Object` stored in `model` at this position
//         if let Some(obj) = list_item.item() {
//           if let Ok(row) = obj.downcast::<T>() {
//             // call the user-provided mapper to get a `Widget` for this `row`
//             let widget = (row_mapper_clone.as_ref())(&row);
//             hbox.append(&widget);
//           }
//         }
//       });
//     }

//     GenericListView {
//       container,
//       list_view,
//       scrolled,
//       search_entry,
//       search_bar,
//       model,
//       filter_model,
//       sort_model,
//       row_mapper: noop_mapper,
//       _marker: PhantomData,
//     }
//   }

//   /// Set the function that turns a `&T` → `gtk4::Widget` (your 4-column row UI).
//   /// Must be called *before* `set_items`.
//   ///
//   /// Example mapper:
//   /// ```ignore
//   /// view.set_row_mapper(|row: &MyRowObject| {
//   ///   // MyRowObject has properties “col1”, “col2”, “col3”, “col4”
//   ///   let hbox = gtk4::Box::new(gtk4::Orientation::Horizontal, 12);
//   ///   let l1 = gtk4::Label::new(Some(&row.property::<String>("col1")));
//   ///   let l2 = gtk4::Label::new(Some(&row.property::<String>("col2")));
//   ///   let l3 = gtk4::Label::new(Some(&row.property::<String>("col3")));
//   ///   let l4 = gtk4::Label::new(Some(&row.property::<String>("col4")));
//   ///   hbox.append(&l1);
//   ///   hbox.append(&l2);
//   ///   hbox.append(&l3);
//   ///   hbox.append(&l4);
//   ///   hbox.upcast::<gtk4::Widget>()
//   /// });
//   /// ```
//   pub fn set_row_mapper<F>(&mut self, f: F) -> &mut Self
//   where
//     F: Fn(&T) -> gtk4::Widget + 'static,
//   {
//     self.row_mapper = Arc::new(f);
//     // Update the factory’s bind closure to use the new mapper
//     //
//     // We need to disconnect the old “bind” and reconnect. Easiest is to
//     // create a brand‐new factory and reassign it to `list_view`. But for brevity:
//     //
//     // Here’s a quick & dirty way: clear all existing signal handlers on the Factory,
//     // then re‐attach `setup` and `bind` with the new mapper. In production, you might
//     // keep a reference to the handler IDs instead of doing `disconnect()` on all.
//     //
//     let (factory,) = self.list_view.factory().unwrap().into();
//     factory.disconnect_by_func(|_| ());
//     let mapper_clone = self.row_mapper.clone();
//     factory.connect_setup(move |_f, item| {
//       let hbox = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
//       hbox.set_margin_all(4);
//       item.set_child(Some(&hbox));
//     });
//     factory.connect_bind(move |_f, list_item| {
//       let hbox = list_item.child().unwrap().downcast::<gtk4::Box>().unwrap();
//       hbox.remove_all();
//       if let Some(obj) = list_item.item() {
//         if let Ok(row) = obj.downcast::<T>() {
//           let widget = (mapper_clone.as_ref())(&row);
//           hbox.append(&widget);
//         }
//       }
//     });

//     self
//   }

//   /// Populate the model with a slice of `T` (which must be `glib::Object`).
//   /// This *replaces* all previous items. (For very large lists, you might do incremental loads,
//   /// but this simply clears + appends all.)
//   pub fn set_items(&self, items: &[T]) {
//     // 1) clear existing
//     self.model.remove_all();
//     // 2) append each `T` (cloning the reference)
//     for item in items {
//       self.model.append(item);
//     }
//   }

//   /// Enable sorting by some `glib::Object` property on `T`.
//   /// `sort_prop` is the name of a `String` property on your `T`.
//   /// `ascending == true` → A→Z; `false` → Z→A.
//   pub fn enable_sorting(&mut self, sort_prop: &str, ascending: bool) -> &mut Self {
//     let prop_name = sort_prop.to_string();
//     let sorter = gtk4::CustomSorter::new(move |a, b| {
//       let ta = a.downcast_ref::<T>().unwrap();
//       let tb = b.downcast_ref::<T>().unwrap();
//       let va = ta.property::<String>(&prop_name);
//       let vb = tb.property::<String>(&prop_name);
//       if ascending { va.cmp(&vb) } else { vb.cmp(&va) }
//     });
//     self.sort_model.set_sorter(Some(&sorter));
//     self
//   }

//   /// Return the selected rows as a Vec<T> (cloned references).
//   pub fn get_selected(&self) -> Vec<T> {
//     let selection = self.list_view.selection();
//     let mut result = Vec::new();
//     if let Some(selected_items) = selection.selected_items() {
//       for obj in selected_items.iter() {
//         if let Ok(row) = obj.clone().downcast::<T>() {
//           result.push(row);
//         }
//       }
//     }
//     result
//   }
// }
