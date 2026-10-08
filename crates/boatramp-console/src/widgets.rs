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
    let on_click = props
        .on_retry
        .clone()
        .map(|cb| Callback::from(move |_: MouseEvent| cb.emit(())));
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
                <span class="mt-1 block text-xs text-slate-500">{ hint }</span>
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
                <span class="mt-1 block text-xs text-slate-500">{ hint }</span>
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

/// Shared text-`<input>` classes, including the focus ring, for the hand-rolled
/// (ref-based / uncontrolled) inputs that don't go through [`TextField`]. Keeps
/// every input's focus affordance consistent (an a11y must).
pub const INPUT: &str = "w-full rounded-md border border-slate-300 px-2.5 py-1.5 text-sm shadow-sm \
     focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500";
/// Shared `<select>` classes (with the focus ring).
pub const SELECT: &str = "rounded-md border border-slate-300 px-2.5 py-1.5 text-sm shadow-sm \
     focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500";

/// A button's visual weight. The weight encodes blast radius so an operator can
/// learn it: solid rose = irreversible, outline rose = reversible/row-level.
#[derive(Clone, Copy, PartialEq)]
pub enum BtnVariant {
    /// The single accent (sky) — a commit action (Save / Mint / Set / Start).
    Primary,
    /// Neutral outline — a non-committing or read action.
    Secondary,
    /// Solid rose — an IRREVERSIBLE action (prune delete, blob purge, KV import,
    /// revoke node/token, remove root anchor).
    Danger,
    /// Outline rose — a reversible / row-level removal (alias, challenge, user).
    DangerSubtle,
}

impl BtnVariant {
    fn classes(self) -> &'static str {
        match self {
            BtnVariant::Primary => "bg-sky-600 text-white hover:bg-sky-700",
            BtnVariant::Secondary => "border border-slate-300 text-slate-700 hover:bg-slate-50",
            BtnVariant::Danger => "bg-rose-600 text-white hover:bg-rose-700",
            BtnVariant::DangerSubtle => "border border-rose-300 text-rose-700 hover:bg-rose-50",
        }
    }
}

/// The shared button: a [`BtnVariant`] weight, a baked-in in-flight (`busy`)
/// state that disables (so a mutating action can't double-fire) and swaps the
/// label, a `disabled` prop, and a consistent focus ring.
#[derive(Properties, PartialEq)]
pub struct ButtonProps {
    /// The button text.
    pub label: AttrValue,
    /// Visual weight / blast radius.
    #[prop_or(BtnVariant::Secondary)]
    pub variant: BtnVariant,
    /// While `true`, the button is disabled and shows `busy_label` (or the label).
    #[prop_or_default]
    pub busy: bool,
    /// The label to show while `busy` (e.g. "Saving…"); defaults to `label`.
    #[prop_or_default]
    pub busy_label: Option<AttrValue>,
    /// Disable regardless of `busy` (e.g. nothing to save).
    #[prop_or_default]
    pub disabled: bool,
    /// Click handler.
    #[prop_or_default]
    pub onclick: Callback<MouseEvent>,
}

#[function_component(Button)]
pub fn button(props: &ButtonProps) -> Html {
    let label = if props.busy {
        props
            .busy_label
            .clone()
            .unwrap_or_else(|| props.label.clone())
    } else {
        props.label.clone()
    };
    html! {
        <button type="button" onclick={props.onclick.clone()}
                disabled={props.busy || props.disabled}
                class={classes!(
                    "rounded-md", "px-3", "py-1.5", "text-sm", "font-medium",
                    "focus-visible:outline-none", "focus-visible:ring-2",
                    "focus-visible:ring-sky-500", "focus-visible:ring-offset-2",
                    "disabled:opacity-50", "disabled:pointer-events-none",
                    props.variant.classes()
                )}>
            { label }
        </button>
    }
}

/// A small copy-to-clipboard button with a transient "Copied" state, for the
/// "shown once" secrets (a minted token / a join token) where manual text
/// selection is error-prone (a slip means re-minting).
#[derive(Properties, PartialEq)]
pub struct CopyButtonProps {
    /// The exact text copied to the clipboard.
    pub value: AttrValue,
}

#[function_component(CopyButton)]
pub fn copy_button(props: &CopyButtonProps) -> Html {
    let copied = use_state(|| false);
    let onclick = {
        let copied = copied.clone();
        let value = props.value.to_string();
        Callback::from(move |_: MouseEvent| {
            if let Some(nav) = web_sys::window().map(|w| w.navigator()) {
                let _ = nav.clipboard().write_text(&value);
            }
            copied.set(true);
            let copied = copied.clone();
            gloo_timers::callback::Timeout::new(1500, move || copied.set(false)).forget();
        })
    };
    html! {
        <button type="button" onclick={onclick}
                class="shrink-0 rounded-md border border-slate-300 px-2 py-1 text-xs font-medium \
                       text-slate-600 hover:bg-slate-50 focus-visible:outline-none \
                       focus-visible:ring-2 focus-visible:ring-sky-500 focus-visible:ring-offset-2">
            { if *copied { "Copied" } else { "Copy" } }
        </button>
    }
}

/// A titled card section. An optional right-aligned header `action` (e.g. a
/// Refresh/Delete button) and an optional `description` line under the title —
/// so views stop hand-duplicating this shell.
#[derive(Properties, PartialEq)]
pub struct SectionProps {
    /// The section title.
    pub title: AttrValue,
    /// Optional one-line description under the title.
    #[prop_or_default]
    pub description: Option<AttrValue>,
    /// Optional right-aligned control in the header.
    #[prop_or_default]
    pub action: Html,
    /// The section body.
    pub children: Html,
}

#[function_component(Section)]
pub fn section(props: &SectionProps) -> Html {
    html! {
        <section class="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <div class="mb-4 flex items-start justify-between gap-3">
                <div>
                    <h3 class="text-base font-semibold text-slate-900">{ &props.title }</h3>
                    if let Some(desc) = &props.description {
                        <p class="mt-0.5 text-sm text-slate-500">{ desc }</p>
                    }
                </div>
                { props.action.clone() }
            </div>
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
