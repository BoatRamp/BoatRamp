//! Small shared UI widgets (loading, error, empty states) reused across views.

use yew::prelude::*;

/// A centered loading indicator with a label.
#[derive(Properties, PartialEq)]
pub struct SpinnerProps {
    /// Text shown beside the spinner.
    #[prop_or_default]
    pub label: AttrValue,
}

#[function_component(Spinner)]
pub fn spinner(props: &SpinnerProps) -> Html {
    html! {
        <div class="flex items-center justify-center gap-3 py-10 text-slate-500">
            <span class="h-4 w-4 animate-spin rounded-full border-2 border-slate-300 border-t-sky-600" />
            <span class="text-sm">{ &props.label }</span>
        </div>
    }
}

/// An error banner with an optional retry button.
#[derive(Properties, PartialEq)]
pub struct ErrorBannerProps {
    /// The error message.
    pub message: AttrValue,
    /// When set, a "Retry" button emits this.
    #[prop_or_default]
    pub on_retry: Option<Callback<()>>,
}

#[function_component(ErrorBanner)]
pub fn error_banner(props: &ErrorBannerProps) -> Html {
    let on_click = props.on_retry.clone().map(|cb| {
        Callback::from(move |_: MouseEvent| cb.emit(()))
    });
    html! {
        <div class="flex items-center justify-between rounded-lg border border-rose-200 bg-rose-50 px-4 py-3">
            <p class="text-sm text-rose-700">{ &props.message }</p>
            if let Some(on_click) = on_click {
                <button onclick={on_click}
                        class="rounded-md border border-rose-300 bg-white px-2.5 py-1 text-sm \
                               font-medium text-rose-700 hover:bg-rose-100">
                    { "Retry" }
                </button>
            }
        </div>
    }
}

/// A small status pill (`text` styled by `tone`).
#[derive(Clone, Copy, PartialEq)]
pub enum Tone {
    /// Green — success / live.
    Good,
    /// Slate — neutral.
    Neutral,
    /// Amber — warning.
    Warn,
    /// Rose — error.
    Bad,
}

impl Tone {
    fn classes(self) -> &'static str {
        match self {
            Tone::Good => "bg-emerald-100 text-emerald-700",
            Tone::Neutral => "bg-slate-100 text-slate-600",
            Tone::Warn => "bg-amber-100 text-amber-700",
            Tone::Bad => "bg-rose-100 text-rose-700",
        }
    }
}

#[derive(Properties, PartialEq)]
pub struct PillProps {
    /// The pill text.
    pub text: AttrValue,
    /// The colour tone.
    #[prop_or(Tone::Neutral)]
    pub tone: Tone,
}

#[function_component(Pill)]
pub fn pill(props: &PillProps) -> Html {
    html! {
        <span class={classes!(
            "rounded-full", "px-2", "py-0.5", "text-xs", "font-medium",
            props.tone.classes()
        )}>
            { &props.text }
        </span>
    }
}

/// A labeled single-line text input whose value changes emit `on_change`.
#[derive(Properties, PartialEq)]
pub struct TextFieldProps {
    /// Field label.
    pub label: AttrValue,
    /// Current value.
    pub value: AttrValue,
    /// Placeholder text.
    #[prop_or_default]
    pub placeholder: AttrValue,
    /// Optional helper text under the field.
    #[prop_or_default]
    pub hint: Option<AttrValue>,
    /// Render with a monospace font (for hosts / hashes).
    #[prop_or_default]
    pub mono: bool,
    /// Emits the new string on every input event.
    pub on_change: Callback<String>,
}

#[function_component(TextField)]
pub fn text_field(props: &TextFieldProps) -> Html {
    let on_input = {
        let on_change = props.on_change.clone();
        Callback::from(move |e: InputEvent| {
            let value = input_value(&e);
            on_change.emit(value);
        })
    };
    let font = if props.mono { "font-mono" } else { "" };
    html! {
        <label class="block">
            <span class="block text-sm font-medium text-slate-700">{ &props.label }</span>
            <input value={props.value.clone()} placeholder={props.placeholder.clone()}
                   oninput={on_input}
                   class={classes!(
                       "mt-1", "w-full", "rounded-md", "border", "border-slate-300",
                       "px-2.5", "py-1.5", "text-sm", "shadow-sm",
                       "focus:border-sky-500", "focus:outline-none", "focus:ring-1",
                       "focus:ring-sky-500", font
                   )} />
            if let Some(hint) = &props.hint {
                <span class="mt-1 block text-xs text-slate-400">{ hint }</span>
            }
        </label>
    }
}

/// A labeled multi-line textarea (used for newline-separated lists). Value
/// changes emit `on_change`.
#[derive(Properties, PartialEq)]
pub struct TextAreaFieldProps {
    /// Field label.
    pub label: AttrValue,
    /// Current value.
    pub value: AttrValue,
    /// Optional helper text under the field.
    #[prop_or_default]
    pub hint: Option<AttrValue>,
    /// Visible rows.
    #[prop_or(3)]
    pub rows: u32,
    /// Emits the new string on every input event.
    pub on_change: Callback<String>,
}

#[function_component(TextAreaField)]
pub fn textarea_field(props: &TextAreaFieldProps) -> Html {
    let on_input = {
        let on_change = props.on_change.clone();
        Callback::from(move |e: InputEvent| on_change.emit(input_value(&e)))
    };
    html! {
        <label class="block">
            <span class="block text-sm font-medium text-slate-700">{ &props.label }</span>
            <textarea value={props.value.clone()} rows={props.rows.to_string()} oninput={on_input}
                      class="mt-1 w-full rounded-md border border-slate-300 px-2.5 py-1.5 text-sm \
                             font-mono shadow-sm focus:border-sky-500 focus:outline-none \
                             focus:ring-1 focus:ring-sky-500" />
            if let Some(hint) = &props.hint {
                <span class="mt-1 block text-xs text-slate-400">{ hint }</span>
            }
        </label>
    }
}

/// A labeled checkbox; toggles emit `on_change` with the new checked state.
#[derive(Properties, PartialEq)]
pub struct CheckFieldProps {
    /// The label beside the box.
    pub label: AttrValue,
    /// Current checked state.
    pub checked: bool,
    /// Emits the new checked state on toggle.
    pub on_change: Callback<bool>,
}

#[function_component(CheckField)]
pub fn check_field(props: &CheckFieldProps) -> Html {
    let on_change = {
        let on_change = props.on_change.clone();
        Callback::from(move |e: Event| {
            let checked = e
                .target_dyn_into::<web_sys::HtmlInputElement>()
                .map(|el| el.checked())
                .unwrap_or(false);
            on_change.emit(checked);
        })
    };
    html! {
        <label class="flex items-center gap-2">
            <input type="checkbox" checked={props.checked} onchange={on_change}
                   class="h-4 w-4 rounded border-slate-300 text-sky-600 focus:ring-sky-500" />
            <span class="text-sm text-slate-700">{ &props.label }</span>
        </label>
    }
}

/// A collapsible section wrapper used to group the config editor's panels.
#[derive(Properties, PartialEq)]
pub struct SectionProps {
    /// The section title.
    pub title: AttrValue,
    /// The section body.
    pub children: Html,
}

#[function_component(Section)]
pub fn section(props: &SectionProps) -> Html {
    html! {
        <section class="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <h3 class="mb-4 text-base font-semibold text-slate-900">{ &props.title }</h3>
            <div class="space-y-4">{ props.children.clone() }</div>
        </section>
    }
}

/// Read the current value from an `<input>`/`<textarea>` input event.
fn input_value(e: &InputEvent) -> String {
    use wasm_bindgen::JsCast;
    let target = e.target().expect("input event has a target");
    if let Some(input) = target.dyn_ref::<web_sys::HtmlInputElement>() {
        return input.value();
    }
    if let Some(area) = target.dyn_ref::<web_sys::HtmlTextAreaElement>() {
        return area.value();
    }
    String::new()
}
