pub fn message_box(window: &gtk4::ApplicationWindow, message: impl AsRef<str>, detail: impl AsRef<str>, buttons: Option<Vec<&str>>) {
  let buttons = buttons.unwrap_or_else(|| vec!["Ok"]);
  let alert = gtk4::AlertDialog::builder().modal(true).message(message.as_ref()).detail(detail.as_ref()).buttons(buttons).default_button(1).cancel_button(0).build();
  alert.choose(Some(window), None::<&gtk4::gio::Cancellable>, move |res| if res == Ok(1) {});
}
