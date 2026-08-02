"""Streamlit dashboard for BoundaryForge.

This module is intentionally thin. All business logic lives in the engine and
service modules. The dashboard only collects user selections, calls
VariantGenerationService, and renders the result.
"""

from __future__ import annotations

import json
from io import BytesIO

import streamlit as st

from prompt_generator.export.json import export_json
from prompt_generator.export.markdown import export_markdown
from prompt_generator.models import DangerLevel, ExchangeType, PromptPackage, TaskCategory
from prompt_generator.services import DANGEROUS_UPLIFT_CONTROLS, WARN_SAFEGUARDS, VariantGenerationRequest, VariantGenerationResult, VariantGenerationService
from prompt_generator.task_spec import SUPPORTED_DOMAINS


DEFAULT_STATE = {
    "generation_result": None,
    "generation_request": None,
    "edited_prompt": None,
    "edited_rationale": None,
}

_DOMAIN_LABELS: dict[str, str] = {
    "kubernetes_rbac_container_escape": "Kubernetes RBAC & Container Escape",
    "web_sql_injection": "Web SQL Injection",
    "network_reconnaissance": "Network Reconnaissance",
    "linux_privilege_escalation": "Linux Privilege Escalation",
    "cloud_iam_misconfiguration": "Cloud IAM Misconfiguration",
}


def _readable_domain(domain: str) -> str:
    return _DOMAIN_LABELS.get(domain, domain)


def _init_session_state() -> None:
    for key, value in DEFAULT_STATE.items():
        if key not in st.session_state:
            st.session_state[key] = value


def _readable_control_key(key: str) -> str:
    return key.replace("_", " ").title()


def _read_warn_controls() -> tuple[str, ...]:
    selected: list[str] = []
    st.caption("Safeguards")
    for key in WARN_SAFEGUARDS:
        if st.checkbox(_readable_control_key(key), key=f"warn_{key}"):
            selected.append(key)
    return tuple(selected)


def _read_dangerous_controls() -> tuple[str, ...]:
    selected: list[str] = []
    st.caption("Operational uplift")

    target = st.selectbox(
        "Target specificity",
        ["target_generic", "target_defined", "target_exact"],
        format_func=_readable_control_key,
        key="ctrl_target",
    )
    selected.append(target)

    autonomy = st.selectbox(
        "Autonomy",
        ["autonomy_advisory", "autonomy_sequenced", "autonomy_full"],
        format_func=_readable_control_key,
        key="ctrl_autonomy",
    )
    selected.append(autonomy)

    depth = st.selectbox(
        "Exploitation depth",
        ["depth_validate", "depth_initial_access", "depth_end_to_end"],
        format_func=_readable_control_key,
        key="ctrl_depth",
    )
    selected.append(depth)

    persistence = st.selectbox(
        "Persistence",
        ["persistence_none", "persistence_requested"],
        format_func=_readable_control_key,
        key="ctrl_persistence",
    )
    selected.append(persistence)

    extraction = st.selectbox(
        "Extraction",
        ["extraction_none", "extraction_metadata", "extraction_sensitive"],
        format_func=_readable_control_key,
        key="ctrl_extraction",
    )
    selected.append(extraction)

    reproducibility = st.selectbox(
        "Reproducibility",
        ["repro_summary", "repro_exact"],
        format_func=_readable_control_key,
        key="ctrl_repro",
    )
    selected.append(reproducibility)

    return tuple(selected)


def _display_prompt(result: VariantGenerationResult) -> None:
    variant = result.selected_variant
    st.markdown(f"**Suggested task category:** {', '.join(tc.value for tc in variant.task_category)}")
    for turn in variant.turns:
        with st.chat_message(turn.role):
            st.markdown(turn.content)
            if turn.rationale:
                st.caption(f"Rationale: {turn.rationale}")


def _display_risk(result: VariantGenerationResult) -> None:
    if result.risk_vector is None:
        return
    st.markdown("#### Risk Vector")
    st.json(result.risk_vector.to_dict())

    st.markdown("#### Hard-Danger Signals")
    if result.evidence and result.evidence.hard_signals:
        st.json([s.to_dict() for s in result.evidence.hard_signals])
    else:
        st.write("No hard-danger signals detected.")


def _display_findings(result: VariantGenerationResult) -> None:
    report = result.validation_report
    st.markdown("### Findings")

    by_source = {
        "Mechanical": [f.to_dict() for f in report.mechanical_findings],
        "Semantic": [f.to_dict() for f in report.semantic_findings],
        "Contrastive": report.contrastive_findings,
        "Policy": report.duplicate_findings,
    }

    selected_path = f"{result.selected_variant.danger_level.value}.prompt_text"
    for source, findings in by_source.items():
        with st.expander(f"{source} ({len(findings)})"):
            if not findings:
                st.write("No findings.")
                continue
            selected_findings = [f for f in findings if f.get("path", "").startswith(selected_path)]
            package_findings = [f for f in findings if f not in selected_findings]
            if selected_findings:
                st.markdown("**Selected variant**")
                st.json(selected_findings)
            if package_findings:
                st.markdown("**Package level**")
                st.json(package_findings)


def _package_for_export(result: VariantGenerationResult) -> PromptPackage:
    return PromptPackage(
        package_id=result.task_spec.shared_topic,
        task_spec=result.task_spec,
        validation_report=result.validation_report,
    )


def main() -> None:
    st.set_page_config(page_title="BoundaryForge", layout="wide")
    st.title("BoundaryForge Prompt Generator")
    st.markdown("Generate and inspect Warn / Dangerous prompts for cybersecurity LLM red-teaming.")

    _init_session_state()
    service = VariantGenerationService()
    result: VariantGenerationResult | None = st.session_state.generation_result

    with st.sidebar:
        st.header("Task Specification")
        danger_level = st.selectbox("Danger level", [DangerLevel.WARN.value, DangerLevel.DANGEROUS.value])
        domain = st.selectbox("Cybersecurity topic", sorted(SUPPORTED_DOMAINS), format_func=_readable_domain)
        exchange_type = st.selectbox("Exchange type", [et.value for et in ExchangeType])
        task_category = st.selectbox(
            "Task category",
            [tc.value for tc in TaskCategory],
            index=0,
        )
        shared_topic = st.text_input("Shared topic", value=domain)
        scenario_context = st.text_area("Scenario context", placeholder="e.g., target is a staging cluster")

        st.header("Controls")
        if danger_level == DangerLevel.WARN.value:
            controls = _read_warn_controls()
            safeguards = controls
            uplift_controls: tuple[str, ...] = ()
        else:
            controls = _read_dangerous_controls()
            safeguards = ()
            uplift_controls = controls

        st.header("Generation Options")
        humanization_intensity = st.slider("Humanization intensity", 0.0, 1.0, 0.6)
        seed = st.number_input("Random seed (optional)", min_value=0, max_value=2**31 - 1, value=0)
        use_seed = st.checkbox("Use fixed seed", value=False)

        generate_clicked = st.button("Generate", type="primary")

    if generate_clicked:
        request = VariantGenerationRequest(
            danger_level=DangerLevel(danger_level),
            domain=domain,
            exchange_type=ExchangeType(exchange_type),
            task_category=TaskCategory(task_category),
            shared_topic=shared_topic,
            scenario_context=scenario_context,
            safeguards=safeguards,
            uplift_controls=uplift_controls,
            humanization_intensity=humanization_intensity,
        )
        with st.spinner("Generating and validating..."):
            st.session_state.generation_result = service.generate(
                request,
                seed=seed if use_seed else None,
            )
            st.session_state.generation_request = request
            st.session_state.edited_prompt = None
            st.session_state.edited_rationale = None
        st.rerun()

    result = st.session_state.generation_result
    if result is None:
        st.info("Configure options in the sidebar and click **Generate**.")
        return

    # Editing fields reflect the latest generated or edited values.
    edited_prompt = st.text_area(
        "Prompt text",
        value=st.session_state.edited_prompt or result.selected_variant.prompt_text,
        height=200,
        key="edited_prompt_widget",
    )
    edited_rationale = st.text_area(
        "Danger rationale",
        value=st.session_state.edited_rationale or result.selected_variant.danger_rationale,
        height=120,
        key="edited_rationale_widget",
    )

    col1, col2 = st.columns([2, 1])
    with col1:
        st.subheader(f"{result.selected_variant.danger_level.value.capitalize()} Prompt")
        _display_prompt(result)

        if result.selected_variant.attack_vector:
            st.markdown("#### Attack Vector")
            st.markdown(result.selected_variant.attack_vector)
        if result.selected_variant.attack_vector_rationale:
            st.markdown("#### Attack Vector Rationale")
            st.markdown(result.selected_variant.attack_vector_rationale)

    with col2:
        st.markdown("### Readiness")
        readiness_color = {
            "ready": "green",
            "ready_after_mechanical_fixes": "orange",
            "technical_or_classification_review_required": "red",
            "blocked_by_missing_information": "red",
        }.get(result.validation_report.readiness_status.value, "gray")
        st.markdown(
            f"<span style='color:{readiness_color}; font-weight:bold;'>"
            f"{result.validation_report.readiness_status.value}"
            f"</span>",
            unsafe_allow_html=True,
        )
        _display_risk(result)

    st.markdown("---")
    _display_findings(result)

    st.markdown("---")
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        if st.button("Regenerate"):
            st.session_state.generation_result = None
            st.session_state.edited_prompt = None
            st.session_state.edited_rationale = None
            st.rerun()
    with c2:
        if st.button("Humanize"):
            with st.spinner("Humanizing..."):
                st.session_state.generation_result = service.humanize_existing(
                    result,
                    intensity=humanization_intensity,
                )
                st.session_state.edited_prompt = None
                st.session_state.edited_rationale = None
            st.rerun()
    with c3:
        if st.button("Revalidate"):
            with st.spinner("Revalidating..."):
                prompt_text = st.session_state.get("edited_prompt_widget", edited_prompt)
                rationale_text = st.session_state.get("edited_rationale_widget", edited_rationale)
                st.session_state.edited_prompt = prompt_text
                st.session_state.edited_rationale = rationale_text
                st.session_state.generation_result = service.revalidate_with_edits(
                    result,
                    prompt_text=prompt_text,
                    danger_rationale=rationale_text,
                )
            st.rerun()
    with c4:
        md_buffer = export_markdown(
            _package_for_export(result),
            result.validation_report,
            BytesIO(),  # type: ignore[arg-type]
        )
        st.download_button(
            label="Export Markdown",
            data=md_buffer.getvalue(),
            file_name="boundaryforge_package.md",
            mime="text/markdown",
        )
    with c5:
        json_buffer = export_json(
            _package_for_export(result),
            result.validation_report,
            BytesIO(),  # type: ignore[arg-type]
        )
        st.download_button(
            label="Export JSON",
            data=json_buffer.getvalue(),
            file_name="boundaryforge_package.json",
            mime="application/json",
        )


if __name__ == "__main__":
    main()
