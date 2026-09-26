from __future__ import annotations

import copy
import threading
import time
from typing import Literal

from fastapi import FastAPI, Header, HTTPException, Response as FastAPIResponse, status
from pydantic import BaseModel, Field

ChaosMode = Literal[
    "normal", "false_200", "timeout", "delayed_write", "amount_mismatch", "partial_success"
]


class InvoiceIn(BaseModel):
    invoice_id: str = Field(min_length=1, max_length=255)
    amount: float
    currency: str = Field(min_length=3, max_length=3)


class ChaosModeIn(BaseModel):
    mode: ChaosMode


class State:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.mode: ChaosMode = "normal"
        self.invoices: dict[str, dict[str, object]] = {}
        self.idempotency: dict[str, dict[str, object]] = {}
        self.alerts: list[dict[str, object]] = []

    def clear(self) -> None:
        with self.lock:
            self.mode = "normal"
            self.invoices.clear()
            self.idempotency.clear()
            self.alerts.clear()


state = State()
app = FastAPI(title="FlowProof Mock Accounting", version="0.6.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/chaos/mode")
def set_chaos_mode(payload: ChaosModeIn) -> dict[str, str]:
    with state.lock:
        state.mode = payload.mode
    return {"mode": payload.mode}


@app.delete("/state", status_code=status.HTTP_204_NO_CONTENT)
def clear_state() -> None:
    state.clear()


@app.post("/alerts", status_code=status.HTTP_204_NO_CONTENT)
def receive_alert(payload: dict[str, object]) -> None:
    """Smoke-only generic receiver; production Compose does not include this service."""
    with state.lock:
        state.alerts.append(dict(payload))


@app.get("/alerts")
def list_alerts() -> dict[str, list[dict[str, object]]]:
    with state.lock:
        return {"items": list(state.alerts)}


@app.get("/invoices/{invoice_id}")
def get_invoice(invoice_id: str) -> dict[str, object]:
    with state.lock:
        invoice = state.invoices.get(invoice_id)
    if invoice is None:
        raise HTTPException(status_code=404, detail="invoice not found")
    return {"records": [invoice]}


def persist_after_delay(invoice: dict[str, object]) -> None:
    time.sleep(1.0)
    with state.lock:
        state.invoices[str(invoice["invoice_id"])] = invoice


@app.post("/invoices", status_code=status.HTTP_201_CREATED)
def create_invoice(
    invoice: InvoiceIn,
    http_response: FastAPIResponse,
    idempotency_key: str = Header(alias="Idempotency-Key", min_length=1, max_length=255),
) -> dict[str, object]:
    with state.lock:
        remembered = state.idempotency.get(idempotency_key)
        if remembered is not None:
            http_response.status_code = status.HTTP_200_OK
            return remembered
        mode = state.mode
        record: dict[str, object] = invoice.model_dump()
        if mode == "false_200":
            result = {"accepted": True, "persisted": False, "mode": mode}
            state.idempotency[idempotency_key] = result
            http_response.status_code = status.HTTP_200_OK
            return result
        if mode == "amount_mismatch":
            record["amount"] = round(float(record["amount"]) + 1.0, 2)
        elif mode == "partial_success":
            record.pop("currency")
        if mode == "delayed_write":
            result = {"accepted": True, "persisted": "scheduled", "mode": mode}
            state.idempotency[idempotency_key] = result
            threading.Thread(target=persist_after_delay, args=(copy.deepcopy(record),), daemon=True).start()
            http_response.status_code = status.HTTP_202_ACCEPTED
            return result
        if mode == "timeout":
            # The caller's bounded timeout is the observable result. No side effect is created.
            state.idempotency[idempotency_key] = {"accepted": True, "persisted": False, "mode": mode}
        else:
            if invoice.invoice_id in state.invoices:
                raise HTTPException(status_code=409, detail="invoice already exists")
            state.invoices[invoice.invoice_id] = record
            result = {"accepted": True, "persisted": True, "invoice": record, "mode": mode}
            state.idempotency[idempotency_key] = result
            return result
    time.sleep(10.0)
    return {"accepted": True, "persisted": False, "mode": "timeout"}
